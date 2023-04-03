import socket
import select
import pty
import os
import json
import logging
import traceback

from systemd.journal import JournalHandler

from .argparsing import args
from .session import pollobj, workers
from .logger import log

class Orchestrator:
	_MAIN_PID = os.getpid()

	def __init__(self):
		if args.thread_socket.exists():
			args.thread_socket.unlink()

		self.thread_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		self.thread_listener.bind(str(args.thread_socket))
		self.thread_listener.listen(args.workers)

		self.pollobj = select.epoll()
		self.pollobj.register(self.thread_listener, select.EPOLLIN|select.EPOLLHUP)

	def broadcast(self, message):
		if type(message) == dict:
			message = json.dumps(message)
		if type(message) == str:
			message = message.encode('UTF-8')

		for identifier in workers:
			if workers[identifier]['socket']:
				workers[identifier]['socket'].send(message)

	def send(self, identifier, message):
		if type(message) == dict:
			message = json.dumps(message)
		if type(message) == str:
			message = message.encode('UTF-8')

		if workers[identifier]['socket']:
			try:
				workers[identifier]['socket'].send(message)
			except BrokenPipeError:
				pass

	def register(self, conn, addr, reg_data):
		if (started := reg_data.get('started')) and (identifier := reg_data.get('identifier')):
			print(f"Registring {identifier}->{workers[identifier]['pid']} as a child being alive")
			workers[identifier]['socket'] = conn
			workers[identifier]['alive'] = True

			self.pollobj.register(conn.fileno(), select.EPOLLIN|select.EPOLLHUP)
			self.send(identifier, {"ACTION": "REGISTERED"})

	def spawn(self, identifier):
		pid, child_fd = pty.fork()

		if pid:
			_PARENT = True
			return child_fd
		else:
			log.handlers.remove(log.handlers[0])
			log.addHandler(JournalHandler(SYSLOG_IDENTIFIER=f"slimDNS-{identifier}"))

			try:
				from .workers import Worker
				Worker(parent=self._MAIN_PID, identifier=identifier).run()
			except Exception as error:
				trace = traceback.format_exc()

				log.error(trace)

				# If we didn't get a traceback_message that means the parent
				# process terminated and the client wanted to keep running
				if len(trace):
					with open(f'./crash_{identifier}.log', 'w') as fh:
						fh.write(trace)
				else:
					exit(0)

				exit(1)

			exit(0)

	def run(self):
		transactions = {}
		while True:
			for fd, event in self.pollobj.poll(0.025):
				if fd == self.thread_listener.fileno():
					conn, addr = self.thread_listener.accept()
					r, w, x = select.select([conn], [], [])
					if r:
						self.register(conn, addr, json.loads(conn.recv(8192).decode('UTF-8')))
						# print(conn.recv(1024))
						# conn.send(b'{"ACTION": "CLOSE"}')
					else:
						conn.close()
				else:
					for worker_id in list(workers.keys()):
						if workers[worker_id]['socket'].fileno() == fd:
							data = workers[worker_id]['socket'].recv(8192).decode('UTF-8')

							if not data:
								workers[worker_id]['alive'] = False
								self.pollobj.unregister(workers[worker_id]['socket'].fileno())
								workers[worker_id]['socket'].close()
								del(workers[worker_id])
								continue

							# print(f"slimDNS-{worker_id} sent: {data}")

							message = json.loads(data)

							if message.get('ACTION') == 'PROCESSING-REQUEST':
								if (identifier := message.get('TRANSACTION', {}).get('identifier')) not in transactions:
									transactions[identifier] = message.get('TRANSACTION', {}).get('source')
									self.send(worker_id, {"ACTION": "PROCEED", "TRANSACTION": message.get('TRANSACTION')})
								elif transactions[identifier] != message.get('TRANSACTION', {}).get('source'):
									transactions[identifier] = message.get('TRANSACTION', {}).get('source')
									self.send(worker_id, {"ACTION": "PROCEED", "TRANSACTION": message.get('TRANSACTION')})
								else:
									self.send(worker_id, {"ACTION": "DROP", "TRANSACTION": message.get('TRANSACTION')})
							# elif message.get('ACTION') == 'PROCESSED':
							# 	if (identifier := message.get('TRANSACTION', {}).get('identifier')) in transactions:
							# 		del(transactions[identifier])
							break