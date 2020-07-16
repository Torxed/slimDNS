import json, sys, struct, abc, os, signal, ipaddress #Python v3.3
from socket import *
from select import epoll, EPOLLIN
from collections import OrderedDict

# https://tools.ietf.org/html/rfc1035
# https://tools.ietf.org/html/rfc1034
# https://www.freesoft.org/CIE/Topics/78.htm
# https://www.freesoft.org/CIE/RFC/1035/39.htm
# https://www.freesoft.org/CIE/RFC/1035/43.htm
# https://www.freesoft.org/CIE/RFC/1035/42.htm

UDP = 0b0001
TCP = 0b0010
instances = {}
def server(mode=TCP, *args, **kwargs):
	"""
	server() is essentially just a router.
	It creates a instance of a selected mode (either `TCP` or `UDP`).
	It also saves the instance in a shared instance variable for access later.
	"""
	if mode == TCP:
		instance = TCP_SERVER(*args, **kwargs)
	elif mode == UDP:
		instance = UDP_SERVER(*args, **kwargs)

	instances[f'{instance.config["addr"]}:{instance.config["port"]}'] = instance
	return instance

def byte_to_bin(bs, bin_map=None):
	"""
	Has two functions:

	1) Converts a bytes() type string into a binary representation in str() format

	2) Boundles each binary representation in groups/blocks given by the bin_map list()
	   [1, 1, 2] would group into [['00000000'], ['01010101'], ['10011010', '00110101']]
	   - Any raiming data till be added in a list [...] at the end to not loose data.

	TODO: handle bin_map = None
	"""
	raw = []
	index = 0
	for length in bin_map:
		mipmap = []
		for i in bs[index:index+length]:
			mipmap.append('{0:b}'.format(i).zfill(8))
		raw.append(mipmap)
		index += length
	if index < len(bs):
		mipmap = []
		for i in bs[index:]:
			mipmap.append('{0:b}'.format(i).zfill(8))
		raw.append(mipmap)
	return raw

def bytes_to_hex(b):
	s = ''
	for i in b:
		s += '{:02X}'.format(i) # Int -> HEX
	return s

def bin_str_to_byte(s):
	""" Converts a binary str() representation into a bytes() string """
	b = b''
	for index in range(len(s)):
		b += bytes([int(s[index],2)])
	return b

def ip_to_bytes(ip_obj):
	return struct.pack('>I', int(ip_obj))

class Events():
	"""
	Events.<CONST> is a helper class to indicate which event is triggered.
	Events are passed up through the event chain deep from within slimHTTP.

	These events can be caught in your main `.poll()` loop, and react to different events.
	"""
	SERVER_ACCEPT = 0b10000000
	SERVER_CLOSE = 0b10000001
	SERVER_RESTART = 0b00000010

	CLIENT_DATA = 0b01000000
	CLIENT_REQUEST = 0b01000001
	CLIENT_RESPONSE_DATA = 0b01000010
	CLIENT_UPGRADED = 0b01000011
	CLIENT_UPGRADE_ISSUE = 0b01000100
	CLIENT_URL_ROUTED = 0b01000101
	CLIENT_DATA_FRAGMENTED = 0b01000110
	CLIENT_RESPONSE_PROXY_DATA = 0b01000111

	WS_CLIENT_DATA = 0b11000000
	WS_CLIENT_REQUEST = 0b11000001
	WS_CLIENT_COMPLETE_FRAME = 0b11000010
	WS_CLIENT_INCOMPLETE_FRAME = 0b11000011
	WS_CLIENT_ROUTED = 0b11000100

	NOT_YET_IMPLEMENTED = 0b00000000

	DATA_EVENTS = (CLIENT_RESPONSE_DATA, CLIENT_URL_ROUTED, CLIENT_RESPONSE_PROXY_DATA)

	def convert(_int):
		def_map = {v: k for k, v in Events.__dict__.items() if not k.startswith('__') and k != 'convert'}
		return def_map[_int] if _int in def_map else None

class dns(abc.ABCMeta):
	"""

	Overview: https://www.freesoft.org/CIE/Topics/77.htm
	Overview: https://www.freesoft.org/CIE/RFC/1035/39.htm
	Header: https://www.freesoft.org/CIE/RFC/1035/40.htm
	"""

	@abc.abstractmethod
	def record_type(t):
		types = {
			'a' : 1
		}
		if not t.lower() in types: return None
		return types[t.lower()]

	@abc.abstractmethod
	def record_class(c):
		types = {
			'in' : 1
		}
		if not c.lower() in types: return None
		return types[c.lower()]

	@abc.abstractmethod
	def human_query_type(i):
		types = {
			1 : 'A'
		}
		if not i in types: return None
		return types[i]

	@abc.abstractmethod
	def build_query_field(record):
		response = b''
		for block in record.split(b'.'):
			response += struct.pack('B', len(block))
			response += block
		# record | type | class
		print('Query field:', response + b'\x00\x01' + b'\x00\x01')
		return response + b'\x00' + b'\x00\x01' + b'\x00\x01'

	@abc.abstractmethod
	def build_answer_field(query_type, query, query_meta, cache):
		if not query in cache: raise KeyError(f'DNS record {query} is not in cache: {cache}')
		if not query_type in cache[query]: ValueError(f'DNS record {query} is missing a record for {query_type} requests')

		dns_header_length = 12
		record_pointer_pos = dns_header_length + query_meta['position']
		
		## First we point to the position in the query of the name we're resolving.
		## (to avoid appending unessecary data)
		# Pointers:
		#  https://www.freesoft.org/CIE/RFC/1035/43.htm
		#  https://osqa-ask.wireshark.org/questions/50806/help-understanding-dns-packet-data
		binary_pointer = '11' + bin(record_pointer_pos)[2:].zfill(14)
		pointer = struct.pack('>H', int(binary_pointer, 2))

		record_type = struct.pack('>H', dns.record_type(cache[query][query_type]['type']))
		record_class = struct.pack('>H', dns.record_class(cache[query][query_type]['class']))

		## Then, depending on the TYPE, different data payloads such as TTL etc will be added:
		record_ttl = struct.pack('>I', cache[query][query_type]['ttl'])
		record_length = struct.pack('>H', 4)
		record_data = ip_to_bytes(ipaddress.ip_address(cache[query][query_type]['ip']))

		return pointer + record_type + record_class + record_ttl + record_length + record_data


	@abc.abstractmethod
	def recurse_record(d, data_pos=0, recursed=0):
		if len(d) <= 0: return 0, b''

		query = b''
		query_length = d[0]
		query += d[1:1+query_length]
		parsed_data = 1+query_length

		if query_length == 0 or recursed == 255: # Maximum recursion depth
			return parsed_data, query
		else:
			print('Recursing record:', d[parsed_data:])
			recused_parsed_data, recursed_query = dns.recurse_record(d[parsed_data:], data_pos=data_pos, recursed=recursed)
			return parsed_data+recused_parsed_data, query + b'.' + recursed_query

	@abc.abstractmethod
	def parse_queries(num, data):
		data_pos = 0
		records = OrderedDict()
		for i in range(num):
			parsed_data_index, record = dns.recurse_record(data['bytes'][data_pos:])
			print('Got query from recurse:', record)
			query_type = struct.unpack('>H', data['bytes'][parsed_data_index:parsed_data_index+2])[0]
			query_class = struct.unpack('>H', data['bytes'][parsed_data_index+2:parsed_data_index+2+2])[0]
			records[record[:-1]] = {'type' : query_type, 'class' : query_class, 'position' : data_pos}
			data_pos += parsed_data_index
		return parsed_data_index, records

	@abc.abstractmethod
	def parse_header_flags(headers):
		QR = int(headers['binary'][0][0])
		opcode = int(headers['binary'][0][1:5])
		authorative_answer = int(headers['binary'][0][5])
		truncation = int(headers['binary'][0][6])
		recursion_desired = int(headers['binary'][0][7])
		
		recursion_available = int(headers['binary'][1][0])
		zero_field = int(headers['binary'][1][1:4])
		response_code = int(headers['binary'][1][4:8])

		return {
			'QR' : QR,
			'opcode' : opcode,
			'authorative_answer' : authorative_answer,
			'truncation' : truncation,
			'recursion_desired' : recursion_desired,
			'recursion_available' : recursion_available,
			'zero_field' : zero_field,
			'response_code' : response_code
		}

class DNS_FRAME():
	def __init__(self, CLIENT_IDENTITY):
		self.CLIENT_IDENTITY = CLIENT_IDENTITY

	def parse(self):

		# The struct just maps how many bytes (not bits) per section in a DNS header.
		# A graphic overview can be found here: https://www.freesoft.org/CIE/RFC/1035/40.htm
		dns_header_struct = [2, 2, 2, 2, 2, 2]
		# We then use that struct map to place the values into a dictionary with these keys (in order):
		dns_header_fields = [
			'transaction_id',
			'flags',
			'queries',
			'answers_resource_records',
			'authorities_resource_records',
			'additional_resource_records',
			'data'
		]

		print('RAW:', self.CLIENT_IDENTITY.buffer)
		# data, addr = self.socket.recvfrom(8192)

		## Convert and slot the data into the binary map representation
		binary = list(byte_to_bin(self.CLIENT_IDENTITY.buffer, bin_map=dns_header_struct))

		## Convert the binary representation into the protocol map
		headers = {}
		for index in range(len(binary)):
			headers[dns_header_fields[index]] = {'binary' : binary[index], 'bytes' : bin_str_to_byte(binary[index]), 'hex' : None}
			headers[dns_header_fields[index]]['hex'] = bytes_to_hex(headers[dns_header_fields[index]]['bytes'])

		headers["queries"]["value"] = struct.unpack(">H", headers["queries"]["bytes"])[0]

		self.CLIENT_IDENTITY.server.log(f'[+] Packet from {self.CLIENT_IDENTITY}: {headers["queries"]["value"]}')
		
		#for key, val in headers.items():
		#	print(key, val)
		for option, value in dns.parse_header_flags(headers["flags"]).items():
			headers['flags'][option] = value

		if not headers['flags']['QR'] == 0:
			self.CLIENT_IDENTITY.server.log(f'[-] Warning, Malformed data detected: {self.CLIENT_IDENTITY}')
			return

		responses = OrderedDict()
		with open('records.json', 'r') as fh:
			cache = json.load(fh)

		response = headers['transaction_id']['bytes']
		response += b'\x81\x80' # Flags
		response += b'\x00\x01' # Queries
		response += b'\x00\x01' # answer rrs
		response += b'\x00\x00' # authority rrs
		response += b'\x00\x01' # additional rrs

		query_block = b''
		answer_block = b''

		print('Got queries:', headers["queries"]["value"])
		print('The data:', headers['data'])
		data_block, queries = dns.parse_queries(headers["queries"]["value"], headers["data"])
		for index, query in enumerate(queries):
			query_record = query.decode('UTF-8')
			query_type = dns.human_query_type(queries[query]['type'])
			if query_record in cache and query_type in cache[query_record]:
				query_block += dns.build_query_field(query)
				answer_block += dns.build_answer_field(query_type, query_record, queries[query], cache)
				print(f'[ ] Query {index}: {query_record} -> {cache[query_record][query_type]["ip"]}')
			elif query_record not in cache:
				print(f'[-] DNS record {query_record} is not in cache: {cache}')
			elif not query_type in cache[query]:
				print(f'[-] DNS record {query_record} is missing a record for {query_type} requests')

		response += query_block
		response += answer_block

		if headers['additional_resource_records']:
			response += headers['data']['bytes'][data_block:]

		#if len(answer_block) > 0:
		#	self.socket.sendto(response, addr)

		yield (Events.CLIENT_RESPONSE_DATA, answer_block)

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

			for event, data in DNS_FRAME(self).parse():
				yield (event, data)

				if event in Events.DATA_EVENTS:
					self.socket.send(data)

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

		self.socket.listen(10)

	def log(self, *args, **kwargs):
		"""
		A simple print wrapper, placeholder for more advanced logging in the future.
		Joins any `*args` together and safely calls :func:'str' on each argument.
		"""
		print('[LOG] '.join([str(x) for x in args]))

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
		print(fileno)
		self.pollobj.unregister(fileno)
		self.socket.close()
		if fileno in self.sockets:
			del(self.sockets[fileno])

	def run(self):
		while 1:
			for event, *event_data in self.poll():
				pass