import socket
import json
import time
import select
from ..argparsing import args
from ..helpers import pid_exists

class Worker:
	def __init__(self, parent, identifier):
		self.parent = parent
		self.identifier = identifier
		self._log = open(f'./worker_{self.identifier}.log', 'a')

		self.log(f'Initializing worker {self.identifier}')

		self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.socket.connect(str(args.thread_socket))

		self.send(json.dumps({
			"identifier": self.identifier,
			"started": time.time()
		}))

		self.pollobj = select.epoll()
		self.pollobj.register(self.socket.fileno(), select.EPOLLIN|select.EPOLLHUP)

		self.is_alive = True

	def log(self, *message):
		self._log.write(''.join(message) + '\n')
		self._log.flush()

	def run(self):
		self.log(f'Worker waiting for messages {self.identifier}')

		while self.is_alive and pid_exists(self.parent):
			for fd, event in self.pollobj.poll(1):
				data = self.socket.recv(8192).decode('UTF-8')
				if len(data) == 0:
					self.close(reason="NO_DATA_RECV")

				data = json.loads(data)
				self.log(f"Got data: {data}")

				if data.get('ACTION') == 'CLOSE' and data.get('IDENTIFIER') == self.identifier:
					self.close(reason='PARENT_CLOSE_INSTRUCTION', notify=False)

	def send(self, message, encoding='UTF-8'):
		if type(message) == str:
			message = message.encode(encoding)

		self.log(f'Telling parent {message}')
		self.socket.send(message)
	
	def close(self, reason='CLOSE_CALLED', notify=True):
		self.log(f'Closing worker {self.identifier}')

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

		exit(0)