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
			'a' : 1,
			'ns' : 2,
			'soa' : 6,
			'srv' : 33
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
			1 : 'A',
			2 : 'NS',
			6 : 'SOA',
			33 : 'SRV'
		}
		if not i in types: return None
		return types[i]

	@abc.abstractmethod
	def dns_string(text:bytes):
		bytes_string = b''
		for block in text.split(b'.'):
			bytes_string += struct.pack('B', len(block))
			bytes_string += block
		return bytes_string + b'\x00'

	@abc.abstractmethod
	def build_query_field(query):
		response = dns.dns_string(query['record'])

		# record | type | class
		#print('Query field:', response + b'\x00\x01' + b'\x00\x01')
		return {response + struct.pack('>H', query['_type']) + b'\x00\x01'}

	@abc.abstractmethod
	def A(query, cache, pointers):
		record = query['record'].decode('UTF-8')
		query_type = query['type']

		ip = ip_to_bytes(ipaddress.ip_address(cache[record][query_type]['ip']))

		record = b''.join(OrderedDict({
			'record_name' : pointers[record]['bytes'] if record in pointers else bytes(record, 'UTF-8'),

			'record_type' : struct.pack('>H', dns.record_type(cache[record][query_type]['type'])),
			'class' : struct.pack('>H', dns.record_class(cache[record][query_type]['class'])),
			'ttl' : struct.pack('>I', cache[record][query_type]['ttl']),
			'length' : struct.pack('>H', len(ip)),

			'data' : ip
		}).values())

		return {record}, set()

	@abc.abstractmethod
	def SOA(query, cache, pointers):
		record = query['record'].decode('UTF-8')
		query_type = query['type']

		SOA_specifics = b''.join(OrderedDict({
			'primary_server' : pointers[record]['bytes'] if record in pointers else bytes(record, 'UTF-8'),
			'mailbox' : b'\x04root' + pointers[record]['bytes'] if record in pointers else bytes(record, 'UTF-8'),
			'serial_number' : struct.pack('>i', 1),
			'refresh_interval' : struct.pack('>i', 360),
			'retry_interval' : struct.pack('>i', 360),
			'expire_limit' : struct.pack('>i', 360),
			'ninimum_ttl' : struct.pack('>i', 360)
		}).values())

		record = b''.join(OrderedDict({
			'domain_name' : pointers[record]['bytes'] if record in pointers else bytes(record, 'UTF-8'),

			'record_type' : struct.pack('>H', dns.record_type(cache[record][query_type]['type'])),
			'class' : struct.pack('>H', dns.record_class(cache[record][query_type]['class'])),
			'ttl' : struct.pack('>I', cache[record][query_type]['ttl']),
			'length' : struct.pack('>H', len(SOA_specifics)),

			'data' : SOA_specifics
		}).values())

		return {record}, set() # len(raw_response), raw_response, set()

	@abc.abstractmethod
	def NS(query, cache, pointers):
		record = query['record'].decode('UTF-8')
		query_type = query['type']

		print('NS query:', query)
		print('Type:', cache[record][query_type]['type'])

		ns_target = cache[record][query_type]['target']

		answer_frame = b''.join(OrderedDict({
			'pointer' : pointers[query['record'].decode('UTF-8')]['bytes'],
			'record_type' : struct.pack('>H', dns.record_type(cache[record][query_type]['type'])),
			'class' : struct.pack('>H', dns.record_class(cache[record][query_type]['class'])),
			'ttl' : struct.pack('>I', cache[record][query_type]['ttl']),
			'length' : struct.pack('>H', len(dns.dns_string(bytes(ns_target, 'UTF-8')))),
			'name_server' : dns.dns_string(bytes(ns_target, 'UTF-8'))
		}).values())

		nameserver_pointer = pointers[query['record'].decode('UTF-8')]['length'] + (len(answer_frame) - len(dns.dns_string(bytes(ns_target, 'UTF-8'))))

		pointers[ns_target] = {'position' : nameserver_pointer, 'length' : pointers[query['record'].decode('UTF-8')]['length'] + len(answer_frame), 'bytes' : struct.pack('>H', int('11' + bin(nameserver_pointer)[2:].zfill(14), 2))}

		additional_data = b''.join(OrderedDict({
			'pointer' : pointers[ns_target]['bytes'], # Figure this one out
			'type' : struct.pack('>H', dns.record_type('A')),
			'class' : struct.pack('>H', dns.record_class('in')),
			'ttl' : struct.pack('>i', 60),
			'length' : struct.pack('>H', 4),
			'data' : ip_to_bytes(ipaddress.ip_address(cache[ns_target]['A']['ip']))
		}).values())

		return {answer_frame}, {additional_data}

	@abc.abstractmethod
	def SRV(query, cache, pointers):
		record = query['record'].decode('UTF-8')
		query_type = query['type']

		srv_target = cache[record][query_type]['target']

		answer_data = b''.join(OrderedDict({
			'priority' : struct.pack('>H', cache[record][query_type]['priority']),
			'weight' : b'\x00\x00',
			'port' : struct.pack('>H', cache[record][query_type]['port']),
			'target' : dns.dns_string(bytes(srv_target, 'UTF-8'))
		}).values())
		answer_frame = b''.join(OrderedDict({
			'pointer' : pointers[query['record'].decode('UTF-8')]['bytes'],
			'record_type' : struct.pack('>H', dns.record_type(cache[record][query_type]['type'])),
			'class' : struct.pack('>H', dns.record_class(cache[record][query_type]['class'])),
			'ttl' : struct.pack('>I', cache[record][query_type]['ttl']),
			'length' : struct.pack('>H', len(answer_data)),
			'data' : answer_data
		#   'priority' : struct.pack('>H', cache[record][query_type]['priority']),
		#   'weight' : b'\x00\x00',
		#   'port' : struct.pack('>H', cache[record][query_type]['port']),
		#   'target' : dns.dns_string(bytes(srv_target, 'UTF-8'))
		}).values())
		target_pointer_pos = pointers[query['record'].decode('UTF-8')]['length'] + (len(answer_frame) - len(dns.dns_string(bytes(srv_target, 'UTF-8'))))

		pointers[srv_target] = {'position' : target_pointer_pos, 'length' : pointers[query['record'].decode('UTF-8')]['length'] + len(answer_frame), 'bytes' : struct.pack('>H', int('11' + bin(target_pointer_pos)[2:].zfill(14), 2))}

		additional_data = OrderedDict({
			'pointer' : pointers[srv_target]['bytes'], # Figure this one out
			'type' : struct.pack('>H', dns.record_type('A')),
			'class' : struct.pack('>H', dns.record_class('in')),
			'ttl' : struct.pack('>i', 60),
			'length' : struct.pack('>H', 4),
			'data' : ip_to_bytes(ipaddress.ip_address(cache[srv_target]['A']['ip']))
		})

		additional_data = b''.join(additional_data.values())

		return {answer_frame}, {additional_data}

	@abc.abstractmethod
	def build_answer_field(query, cache, pointers):
		record = query['record'].decode('UTF-8')
		query_type = query['type']
		if not record in cache: raise KeyError(f"DNS record {record} is not in cache: {cache}")
		if not query_type in cache[record]: ValueError(f"DNS record {record} is missing a record for {query_type} requests")

		if hasattr(dns, query_type):
			if(record_response := getattr(dns, query_type)(query, cache, pointers)):
				return {'answers' : record_response[0], 'additionals' : record_response[1]}

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
			recused_parsed_data, recursed_query = dns.recurse_record(d[parsed_data:], data_pos=data_pos, recursed=recursed)
			return parsed_data+recused_parsed_data, query + b'.' + recursed_query

	@abc.abstractmethod
	def parse_queries(num, data):
		data_pos = 0
		records = OrderedDict()
		for i in range(num):
			parsed_data_index, record = dns.recurse_record(data['bytes'][data_pos:])

			#print(record)
			#b'\x07hvornum\x02se\x00\x00\x06\x00\x01'
						
			query_type = struct.unpack('>H', data['bytes'][parsed_data_index:parsed_data_index+2])[0]
			parsed_data_index += 2
			query_class = struct.unpack('>H', data['bytes'][parsed_data_index:parsed_data_index+2])[0]
			parsed_data_index += 2

			records[record[:-1]] = {'_type' : query_type, 'type' : dns.human_query_type(query_type), 'class' : query_class, 'position' : data_pos, 'record' : record[:-1], 'length' : parsed_data_index}
			data_pos += parsed_data_index
		return data_pos, records

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

class DNS_TCP_FRAME():
	def __init__(self, CLIENT_IDENTITY):
		self.CLIENT_IDENTITY = CLIENT_IDENTITY

		# The struct just maps how many bytes (not bits) per section in a DNS header.
		# A graphic overview can be found here: https://www.freesoft.org/CIE/RFC/1035/40.htm
		self.dns_header_struct = [2, 2, 2, 2, 2, 2, 2]
		# We then use that struct map to place the values into a dictionary with these keys (in order):
		self.dns_header_fields = [
			'length',
			'transaction_id',
			'flags',
			'queries',
			'answers_resource_records',
			'authorities_resource_records',
			'additional_resource_records',
			'data'
		]

	def finalize_response(self, response):
		return struct.pack('>H', len(response)) + response

	def parse(self):
		# data, addr = self.socket.recvfrom(8192)

		## Convert and slot the data into the binary map representation
		binary = list(byte_to_bin(self.CLIENT_IDENTITY.buffer, bin_map=self.dns_header_struct))

		## Convert the binary representation into the protocol map
		headers = {}
		for index in range(len(binary)):
			headers[self.dns_header_fields[index]] = {'binary' : binary[index], 'bytes' : bin_str_to_byte(binary[index]), 'hex' : None}
			headers[self.dns_header_fields[index]]['hex'] = bytes_to_hex(headers[self.dns_header_fields[index]]['bytes'])

		headers["queries"]["value"] = struct.unpack(">H", headers["queries"]["bytes"])[0]

		self.CLIENT_IDENTITY.server.log(f'[+] Got {headers["queries"]["value"]} queries from {self.CLIENT_IDENTITY}')
		
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

		dns_header_len = len(self.dns_header_struct)
		pointers = {}

		query_block = set()
		answers = set()
		additionals = set()
		authorities = set()

		parsed_data_index, queries = dns.parse_queries(headers["queries"]["value"], headers["data"])

		## First we point to the position in the query of the name we're resolving.
		## (to avoid appending unessecary data)
		# Pointers:
		#  https://www.freesoft.org/CIE/RFC/1035/43.htm
		#  https://osqa-ask.wireshark.org/questions/50806/help-understanding-dns-packet-data
		for record in queries:
			# 11XXXXXX in binary represents that there's a pointer here in the DNS world.
			# And it has to be exactly 16 bits (2 bytes)
			position = sum(self.dns_header_struct)+queries[record]['position']
			pointers[queries[record]['record'].decode('UTF-8')] = {'position' : position, 'length' : position+queries[record]['length'], 'bytes' : struct.pack('>H', int('11' + bin(position)[2:].zfill(14), 2))}
		
		for index, query in enumerate(queries):
			query_record = query.decode('UTF-8')

			if queries[query]['type'] and query_record in cache and queries[query]['type'] in cache[query_record]:
				query_block |= dns.build_query_field(queries[query])

				if(result := dns.build_answer_field(queries[query], cache, pointers)):
					answers |= result['answers']
					additionals |= result['additionals']
					self.CLIENT_IDENTITY.server.log(f"[ ] Query {index+1}: {query_record} -> {cache[query_record][queries[query]['type']]['ip']}")
				else:
					self.CLIENT_IDENTITY.server.log(f"[ ] While building answer for query {index+1} ({query_record}), dns.{queries[query]['type']} was detected as not implemented as a answer function.")
			elif query_record not in cache:
				self.CLIENT_IDENTITY.server.log(f'[-] DNS record {query_record} is not in cache: {cache}')
			elif queries[query]['type'] and not queries[query]['type'] in cache[query_record]:
				self.CLIENT_IDENTITY.server.log(f"[-] DNS record {query_record} is missing a record for {queries[query]['type']} requests")
			else:
				self.CLIENT_IDENTITY.server.log(f"[-] Record type {queries[query]['type']} is not implemented (While handling {query_record})")

		if headers['additional_resource_records']:
			# wireshark_match = '\\x'+'\\x'.join([hex(i)[2:].zfill(2) for i in headers["data"]['bytes'][parsed_data_index:]])
			# print(wireshark_match)
			additionals |= {headers['data']['bytes'][parsed_data_index:]}

		response = headers['transaction_id']['bytes']
		response += b'\x85\x00' # Flags  b'\x81\x80'
		response += struct.pack('>H', len(query_block)) # Queries
		response += struct.pack('>H', len(answers))     # answer rrs
		response += struct.pack('>H', len(authorities)) # authority rrs
		response += struct.pack('>H', len(additionals))
		response += b''.join(query_block)
		response += b''.join(answers)
		response += b''.join(additionals)

		response = self.finalize_response(response)

		#if len(answers) > 0:
		#	self.socket.sendto(response, addr)

		if len(answers) > 0:
			yield (Events.CLIENT_RESPONSE_DATA, response)

class DNS_UDP_FRAME(DNS_TCP_FRAME):
	def __init__(self, CLIENT_IDENTITY):
		self.CLIENT_IDENTITY = CLIENT_IDENTITY

		# The struct just maps how many bytes (not bits) per section in a DNS header.
		# A graphic overview can be found here: https://www.freesoft.org/CIE/RFC/1035/40.htm
		self.dns_header_struct = [2, 2, 2, 2, 2, 2]
		# We then use that struct map to place the values into a dictionary with these keys (in order):
		self.dns_header_fields = [
			'transaction_id',
			'flags',
			'queries',
			'answers_resource_records',
			'authorities_resource_records',
			'additional_resource_records',
			'data'
		]

	def finalize_response(self, response):
		# UDP doesn't require any additional lengths etc.
		return response

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

			for event, data in DNS_TCP_FRAME(self).parse():
				yield (event, data)

				if event in Events.DATA_EVENTS:
					self.socket.send(data)
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