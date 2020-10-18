from .events import *
from .data import *

class DNS_TCP_CLIENT_IDENTITY():
	def __init__(self, server, client_socket, address, on_close):
		self.on_close = on_close

		self.server = server
		self.socket = client_socket
		self.address = address
		self.buffer_size = 8192

		self.buffer = b''

	def __repr__(self, *args, **kwargs):
		return f"<DNS_TCP_CLIENT_IDENTITY addr={self.address}>"

	def poll(self, timeout=0.01, force_recieve=False):
		if force_recieve or list(self.server.poll(timeout, fileno=self.fileno)):
			try:
				d = self.socket.recv(self.buffer_size)
			except: # There's to many errors that can be thrown here for differnet reasons, SSL, OSError, Connection errors etc.
					# They all mean the same thing, things broke and the client couldn't deliver data accordingly so eject.
				d = ''

			if len(d) == 0:
				self.on_close(self.socket.fileno())
				return None

			self.buffer += d
			yield (Events.CLIENT_DATA, len(self.buffer))

			try:
				for event, data in DNS_TCP_FRAME(self).parse():
					yield (event, data)

					if event in Events.DATA_EVENTS:
						self.socket.send(data)
			except Exception as e:
				print(f'[!] Critical error in parsing {self.address} data: {e}')
			
			self.socket.close()

class DNS_UDP_CLIENT_IDENTITY():
	def __init__(self, server):
		self.server = server
		self.address = None
		self.buffer_size = 8192

		self.buffer = b''

	def __repr__(self, *args, **kwargs):
		return f"<DNS_UDP_CLIENT_IDENTITY addr={self.address}>"

	def poll(self, timeout=0.01, force_recieve=False):
		if force_recieve or list(self.server.poll(timeout, fileno=self.fileno)):
			try:
				d, self.address = self.server.socket.recvfrom(self.buffer_size)
			except: # There's to many errors that can be thrown here for differnet reasons, SSL, OSError, Connection errors etc.
					# They all mean the same thing, things broke and the client couldn't deliver data accordingly so eject.
				d = ''

			if len(d) == 0:
				return None

			self.buffer += d
			yield (Events.CLIENT_DATA, len(self.buffer))

			for event, data in DNS_UDP_FRAME(self).parse():
				yield (event, data)

				if event in Events.DATA_EVENTS and self.address:
					self.server.socket.sendto(data, self.address)