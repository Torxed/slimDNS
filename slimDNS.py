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
		if len(d) <= 0: return 0, []

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


class serve_dns():
	def __init__(self, *args, **kwargs):
		if not 'interface' in kwargs: kwargs['interface'] = ''
		if not 'protocol' in kwargs: kwargs['protocol'] = 'UDP'
		if not 'port' in kwargs: kwargs['port'] = 53
		## Update our self.variable = value references.
		for var, val in kwargs.items():
			self.__dict__[var] = val

		if self.protocol == 'UDP':
			self.socket = socket(AF_INET, SOCK_DGRAM) # UDP
		else:
			self.socket = socket()
		## https://www.freepascal.org/docs-html/current/rtl/sockets/index-2.html
		self.socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.socket.bind((self.interface, self.port))
		#self.socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

		self.main_so_id = self.socket.fileno()
		print(f'[-] Bound to: {{"interface" : "{kwargs["interface"]}", "port" : "{self.port}", "protocol" : "{self.protocol}"}}')

		self.pollobj = epoll()
		self.pollobj.register(self.main_so_id, EPOLLIN)

	def poll(self, timeout=0.001, fileno=None):
		d = dict(self.pollobj.poll(timeout))
		if fileno: return d[fileno] if fileno in d else None
		return d

	def close(self):
		self.pollobj.unregister(self.main_so_id)
		self.socket.close()

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

		if self.poll():
			data, addr = self.socket.recvfrom(8192)

			## Convert and slot the data into the binary map representation
			binary = list(byte_to_bin(data, bin_map=dns_header_struct))

			## Convert the binary representation into the protocol map
			headers = {}
			for index in range(len(binary)):
				headers[dns_header_fields[index]] = {'binary' : binary[index], 'bytes' : bin_str_to_byte(binary[index]), 'hex' : None}
				headers[dns_header_fields[index]]['hex'] = bytes_to_hex(headers[dns_header_fields[index]]['bytes'])

			headers["queries"]["value"] = struct.unpack(">H", headers["queries"]["bytes"])[0]

			print(f'[+] Packet from: {{"addr": "{addr}", "queries" : {headers["queries"]["value"]}}}')
			
			#for key, val in headers.items():
			#	print(key, val)
			for option, value in dns.parse_header_flags(headers["flags"]).items():
				headers['flags'][option] = value

			if not headers['flags']['QR'] == 0:
				print(f'[-] Warning, Malformed data detected: {{"from" : "{addr}", "status" : "denied", "reason" : "Trying to impersonate a server to us."}}')
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

			if len(answer_block) > 0:
				self.socket.sendto(response, addr)
			

if __name__ == '__main__':
	def sig_handler(signal, frame):
		dhcp.close()
		exit(0)
	signal.signal(signal.SIGINT, sig_handler)

	## Basic version of arg.parse() supporting:
	## * --key=value
	## * slimDHCP.py positional1 positional2
	args = {}
	positionals = []
	for arg in sys.argv[1:]:
		if '--' == arg[:2]:
			if '=' in arg:
				key, val = [x.strip() for x in arg[2:].split('=')]
			else:
				key, val = arg[2:], True
			args[key] = val
		else:
			positionals.append(arg)

	dhcp = serve_dns(**args)
	while 1:
		if dhcp.poll():
			dhcp.parse()