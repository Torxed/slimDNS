import socket
import json
import time
import select
import base64

#from systemd.journal import JournalHandler

from ..argparsing import args
from ..helpers import pid_exists, JSON_Typer
from ..logger import log
from .sockets import PromiscSocket

class Worker:
	def __init__(self, parent, identifier):
		self.parent = parent
		self.identifier = identifier
		self._log = open(f'./worker_{self.identifier}.log', 'a')

		#log.handlers.remove(log.handlers[0])
		#log.addHandler(JournalHandler(SYSLOG_IDENTIFIER=f"slimDNS-{self.identifier}"))

		self.log(f'Worker is being initialized.')

		self.transactions = {}

		self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.socket.connect(str(args.thread_socket))

		self.send(json.dumps({
			"identifier": self.identifier,
			"started": time.time()
		}))

		self.pollobj = select.epoll()
		self.pollobj.register(self.socket.fileno(), select.EPOLLIN|select.EPOLLHUP)

		self.dns_socket = PromiscSocket(addr=args.address, port=args.port, buffer_size=args.framesize)
		self.is_alive = True

	def log(self, *message):
		# Log to systemd
		log.info(''.join(message))

		# Log to file
		self._log.write(''.join(message) + '\n')
		self._log.flush()

	def process(self, transaction):
		log.info(f"Processing transaction: {transaction} - {self.transactions.get(transaction)}")


	def run(self):
		self.log(f'Worker is waiting for DNS messages.')

		with self.dns_socket as activated_socket:
			while self.is_alive and pid_exists(self.parent):
				for fd, event in self.pollobj.poll(0.025):
					data = self.socket.recv(8192).decode('UTF-8')

					if len(data) == 0:
						self.close(reason="NO_DATA_RECV")

					data = json.loads(data)
					# self.log(f"Parent told me: {data}")

					if data.get('ACTION') == 'CLOSE' and data.get('IDENTIFIER') == self.identifier:
						self.close(reason='PARENT_CLOSE_INSTRUCTION', notify=False)
					elif (identifier := data.get('TRANSACTION', {}).get('identifier')) and data.get('ACTION') == 'PROCEED':
						self.process(identifier)
					elif data.get('ACTION') == 'DROP' and identifier:
						del(self.transactions[identifier])

				if dns_request := activated_socket.recv():
					self.transactions[base64.b64encode(dns_request.headers.transaction_id).decode('UTF-8')] = dns_request
					self.send({
						"ACTION": "PROCESSING-REQUEST",
						"TRANSACTION": {
							"identifier": dns_request.headers.transaction_id,
							"source": dns_request.addressing.layer3.source
						}
					})
					#print(dns_request)

		exit(0)

	def send(self, message, encoding='UTF-8'):
		if type(message) == dict:
			log.info(str(message))
			message = json.dumps(message, cls=JSON_Typer)
		if type(message) == str:
			message = message.encode(encoding)

		# self.log(f'Telling parent {message}')
		self.socket.send(message)
	
	def close(self, reason='CLOSE_CALLED', notify=True):
		# self.log(f'Closing worker {self.identifier}')

		if notify:
			try:
				self.send(json.dumps({
					"identifier": self.identifier,
					"ended": time.time(),
					"reason": reason
				}))
			except BrokenPipeError:
				# Parent already rejected us
				pass

		self.pollobj.unregister(self.socket.fileno())
		self.socket.close()

		self.is_alive = False
		self._log.close()