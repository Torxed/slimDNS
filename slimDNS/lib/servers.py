from socket import *
from select import epoll, EPOLLIN

from .events import *
from .identities import *

class TCP_SERVER():
	def __init__(self, *args, **kwargs):
		"""
		`__init__` takes ambigious arguments through `**kwargs`.

		:param addr: Address to listen on, default `0.0.0.0`.
		:type addr: str
		:param port: Port to listen on, default `53`.
		:type port: int
		"""
		if not 'port' in kwargs: kwargs['port'] = 53
		if not 'addr' in kwargs: kwargs['addr'] = ''

		self.sockets = {}
		self.config = {**self.default_config(), **kwargs}
		self.setup_socket()
		self.main_sock_fileno = self.socket.fileno()
		
		self.pollobj = epoll()
		self.pollobj.register(self.main_sock_fileno, EPOLLIN)

		self.database = {}
		#if os.path.isfile('./records.json'):
		#	with open('records.json', 'r') as fh:
		#		self.database = json.load(fh)

	def records(self, f, *args, **kwargs):
		if type(db := f(self)) == dict:
			self.database = db

	def log(self, *args, **kwargs):
		"""
		A simple print wrapper, placeholder for more advanced logging in the future.
		Joins any `*args` together and safely calls :func:'str' on each argument.
		"""
		print(' '.join([str(x) for x in args]))

		# TODO: Dump raw requests/logs to a .pcap:  (Optional, if scapy is precent)
		# 
		# from scapy.all import wrpcap, Ether, IP, UDP
		# packet = Ether() / IP(dst="1.2.3.4") / UDP(dport=123)
		# wrpcap('foo.pcap', [packet])

	def setup_socket(self):
		#if self.protocol == 'UDP':
		#	self.socket = socket(AF_INET, SOCK_DGRAM) # UDP

		self.socket = socket()
		## https://www.freepascal.org/docs-html/current/rtl/sockets/index-2.html
		self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.socket.bind((self.config['addr'], self.config['port']))
		self.socket.listen(10)

	def default_config(self):
		"""
		Returns a simple but sane default configuration in case no one is given.

		:return: {'addr' : '', 'port' : 53}
		:rtype: dict
		"""
		return {
			'addr' : '',
			'port' : 53
		}

	def poll(self, timeout=0.001):#, fileno=None):
		# d = dict(self.pollobj.poll(timeout))
		# if fileno: return d[fileno] if fileno in d else None
		# return d
		for socket_fileno, event_type in self.pollobj.poll(timeout):
			if socket_fileno == self.main_sock_fileno:
				for event, event_data in self._on_accept(*self.socket.accept()):
					yield (event, event_data)
			elif socket_fileno in self.sockets:
				for client_event, client_event_data in self.sockets[socket_fileno].poll(timeout, force_recieve=True):
					yield (client_event, client_event_data)
	
	def _on_accept(self, sock, addr):
		fileno = sock.fileno()
		self.sockets[fileno] = DNS_TCP_CLIENT_IDENTITY(self, sock, addr, on_close=self._on_close)
		self.pollobj.register(fileno, EPOLLIN)
		yield (Events.SERVER_ACCEPT, self.sockets[fileno])

	def _on_close(self, fileno=None):
		if not fileno: fileno = self.main_sock_fileno
		self.pollobj.unregister(fileno)
		self.socket.close()
		if fileno in self.sockets:
			del(self.sockets[fileno])

	def run(self):
		while 1:
			for event, *event_data in self.poll():
				pass

class UDP_SERVER(TCP_SERVER):
	def setup_socket(self):
		self.socket = socket(AF_INET, SOCK_DGRAM) # UDP
		## https://www.freepascal.org/docs-html/current/rtl/sockets/index-2.html
		self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.socket.bind((self.config['addr'], self.config['port']))

	def poll(self, timeout=0.001):#, fileno=None):
		# d = dict(self.pollobj.poll(timeout))
		# if fileno: return d[fileno] if fileno in d else None
		# return d
		for socket_fileno, event_type in self.pollobj.poll(timeout):
			if socket_fileno == self.main_sock_fileno:
				for event, CLIENT_IDENTITY in self._on_accept():
					yield (event, CLIENT_IDENTITY)

					if event == Events.SERVER_ACCEPT:
						for client_event, client_event_data in CLIENT_IDENTITY.poll(timeout, force_recieve=True):
							yield (client_event, client_event_data)

	def _on_accept(self, *args, **kwargs):
		yield (Events.SERVER_ACCEPT, DNS_UDP_CLIENT_IDENTITY(self))

	def _on_close(self, fileno=None):
		if not fileno: fileno = self.main_sock_fileno
		self.pollobj.unregister(fileno)
		self.socket.close()
		if fileno in self.sockets:
			del(self.sockets[fileno])

	def run(self):
		while 1:
			for event, *event_data in self.poll():
				pass