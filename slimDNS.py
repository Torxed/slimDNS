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
	byte_to_bin takes a `bytes` string, and groups bytes according to a map.
	The map can be `bin_map=[2, 4, 2]` for instance, which will require a `bytes` string
	of 6 in length. `byte_to_bin` will then split that bytes string into blocks of `2`, `4` and `2`.

	And then convert each block into a binary representation.

	As an example:
	.. code-block:: py

	    >>> byte_to_bin(b'aabbcc', [2, 2, 2])
	    [['01100001', '01100001'], ['01100010', '01100010'], ['01100011', '01100011']]

	.. warning:: `bin_map = None` should return a binary representation of the `bytes` string as-is, but it currently doesn't.

	:param bs: Any kind of `bytes` string is valid.
	:type bs: bytes

	:param bin_map: A list declaring the size of blocks to separate the `bs` into.
	:type bin_map: list

	:return: A list, containing the blocks declared to split in to, where each block is a list of binary representations per character in the block.
	:rtype: list
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

class IncompleteFrame(BaseException):
	pass

class Events():
	"""
	Events.<CONST> is a helper class to indicate which event is triggered.
	Events are passed up through the event chain deep from within slimDNS.

	These events can be caught in your main `.poll()` loop, and react to different events.
	"""
	SERVER_ACCEPT = 0b10000000
	SERVER_CLOSE = 0b10000001
	SERVER_RESTART = 0b00000010

	CLIENT_DATA = 0b01000000
	CLIENT_NO_QUERIES = 0b01000001
	CLIENT_RESPONSE_DATA = 0b01000010
	CLIENT_INVALID_DATA = 0b01000011
	# = 0b01000100
	# = 0b01000101
	# = 0b01000110
	# = 0b01000111

	NOT_YET_IMPLEMENTED = 0b00000000

	DATA_EVENTS = (CLIENT_RESPONSE_DATA,)

	def convert(_int):
		def_map = {v: k for k, v in Events.__dict__.items() if not k.startswith('__') and k != 'convert'}
		return def_map[_int] if _int in def_map else None

class dns(abc.ABCMeta):
	"""
	dns is a abstract class, meant to make it easier to build individual components of DNS frames.
	It also gives the option to convert a data-frame type in numerical value into human readable formats.

	For instance:

	DNS Query Type "1" converts to "A" with the help of `dns.human_query_type(1)`
	DNS Query Type "A" converts to "1" with the help of `dns.record_type('A')`

	Overview: https://www.freesoft.org/CIE/Topics/77.htm
	Overview: https://www.freesoft.org/CIE/RFC/1035/39.htm
	Header: https://www.freesoft.org/CIE/RFC/1035/40.htm
	"""

	@abc.abstractmethod
	def record_type(t):
		"""
		Converts a human readable DNS Type into a integer representation.

		As an example:
		.. code-block:: py

		    >>> record_type('SOA')
		    6

		:param t: A `str` representing a DNS Type, for instance `A` or `MX`.
		:type t: str

		:return: Returns the numerical representation of <Type>
		:rtype: int
		"""
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
		"""
		Converts a human readable DNS Class into a integer representation.

		As an example:
		.. code-block:: py

		    >>> record_class('IN')
		    1

		:param t: A `str` representing a DNS Class, for instance `IN`.
		:type t: str

		:return: Returns the numerical representation of <Class>
		:rtype: int
		"""
		types = {
			'in' : 1
		}
		if not c.lower() in types: return None
		return types[c.lower()]

	@abc.abstractmethod
	def human_query_type(i):
		"""
		Converts a DNS Type from integer into a human readable representation.

		As an example:
		.. code-block:: py

		    >>> human_query_type(33)
		    SRV

		:param i: A `int` representing a DNS Type, for instance 33.
		:type i: int

		:return: Returns the string representation of <Type>
		:rtype: str
		"""
		types = {
			1 : 'A',
			2 : 'NS',
			6 : 'SOA',
			33 : 'SRV'
		}
		if not i in types: return None
		return types[i]

	@abc.abstractmethod
	def string(text:bytes):
		"""
		Builds a DNS String representation.
		A DNS String consists of <length of block 1><block 1><length of block 2><block 2><null byte>

		As an example:
		.. code-block:: py

		    >>> dns.string('example.com')
		    \x07example\x03com\x00

		:param text: A text of any sort, usually a domain name or hostname
		:type text: bytes

		:return: Returns a DNS String compliant version of `text`
		:rtype: bytes
		"""
		if type(text) == str: text = bytes(text, 'UTF-8')
		bytes_string = b''
		for block in text.split(b'.'):
			bytes_string += struct.pack('B', len(block))
			bytes_string += block
		return bytes_string + b'\x00'

	@abc.abstractmethod
	def build_query_field(query):
		"""
		Converts a record or query into a DNS String with TYPE and CLASS.

		As an example:
		.. code-block:: py

		    >>> build_query_field({'record' : 'example.com', '_type' : 1})
		    \x07example\x03com\x00\x00\x01\x00\x01

		Where the individual secions are: `record (len(record)) | type (4) | class (4)`

		:param query: A query `dict` object with keys `type` and `record`.
		:type query: dict

		:return: Returns a data `set` of the record
		:rtype: set
		"""
		record = dns.string(query.record)

		#      record | type | class
		return record + struct.pack('>H', dns.record_type(query.type)) + b'\x00\x01'

	@abc.abstractmethod
	def A(frame, query, database):
		"""
		A helper function to build a DNS "A" record.
		It will build the following structure:

		.. code-block::

		    | Record Name   | // pointer if available
		    | Record Type A | 
		    | Record Class  | // Usually IN class
		    | Record TTL    |
		    | Record Length | // len(ip)
		    | IP address    |
		
		As an example:
		.. code-block:: py

		    >>> A({'record' : 'example.com', '_type' : 1}, database={'example.com' : {'A' : {'ip' : '192.168.0.1', 'type' : 'A', 'class' : 'IN', 'ttl' : 60}}}, pointers={})
		    \x07example\x03com\x00\x00\x01\x00\x01

		Where the individual secions are: `record (len(record)) | type (4) | class (4)`

		:param query: A query `dict` object with keys `type` and `record`.
		:type query: dict

		:return: Returns a data `set` of the record
		:rtype: set
		"""
		ip = ip_to_bytes(ipaddress.ip_address(database[query.record][query.type]['target']))

		return ANSWER(frame, DNS_FIELDS({
			'record_name' : dns.pointer(query.record),
			'record_type' : struct.pack('>H', dns.record_type('A')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record][query.type]['ttl']),
			'length' : struct.pack('>H', len(ip)),

			'data' : ip
		}))

	@abc.abstractmethod
	def SOA(frame, query, database):
		SOA_specifics = DNS_FIELDS({
			'primary_server' : dns.pointer(database[query.record][query.type]['target']),
			'mailbox' : dns.email(f'root@{query.record}'),
			'serial_number' : struct.pack('>i', 1),
			'refresh_interval' : struct.pack('>i', 360),
			'retry_interval' : struct.pack('>i', 360),
			'expire_limit' : struct.pack('>i', 360),
			'ninimum_ttl' : struct.pack('>i', 360)
		})

		return ANSWER(frame, DNS_FIELDS({
			'domain_name' : dns.pointer(query.record),

			'record_type' : struct.pack('>H', dns.record_type('SOA')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record][query.type]['ttl']),
			'length' : struct.pack('>H', len(SOA_specifics)),

			'data' : SOA_specifics
		}))

	@abc.abstractmethod
	def NS(frame, query, database):
		ns_target = database[query.record][query.type]['target']

		answer_frame = ANSWER(frame, {
			'pointer' : dns.pointer(query.record),
			'record_type' : struct.pack('>H', dns.record_type('NS')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record][query.type]['ttl']),
			'length' : struct.pack('>H', len(dns.string(ns_target))),
			'name_server' : dns.string(ns_target)
		})

		additional_data = ADDITIONAL(frame, {
			'pointer' : dns.pointer(ns_target), # Pointers gets resolved at build time, and can be safely stored as a standalone record.
			'type' : struct.pack('>H', dns.record_type('A')),
			'class' : struct.pack('>H', dns.record_class('in')),
			'ttl' : struct.pack('>i', 60),
			'length' : struct.pack('>H', 4),
			'data' : ip_to_bytes(ipaddress.ip_address(database[ns_target]['A']['target']))
		})

		return answer_frame, additional_data

	@abc.abstractmethod
	def SRV(frame, query, database):
		srv_target = database[query.record][query.type]['target']

		answer_data = b''.join(OrderedDict({
			'priority' : struct.pack('>H', database[query.record][query.type]['priority']),
			'weight' : b'\x00\x00',
			'port' : struct.pack('>H', database[query.record][query.type]['port']),
			'target' : dns.string(bytes(srv_target, 'UTF-8'))
		}).values())
		
		return ANSWER(frame, {
			'pointer' : dns.pointer(query.record),
			'record_type' : struct.pack('>H', dns.record_type('SRV')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record][query.type]['ttl']),
			'length' : struct.pack('>H', len(answer_data)),
			'data' : answer_data
		}), ADDITIONAL(frame, {
			'pointer' : dns.pointer(srv_target), # Figure this one out
			'type' : struct.pack('>H', dns.record_type('A')),
			'class' : struct.pack('>H', dns.record_class('in')),
			'ttl' : struct.pack('>i', 60),
			'length' : struct.pack('>H', 4),
			'data' : ip_to_bytes(ipaddress.ip_address(database[srv_target]['A']['target']))
		})

	@abc.abstractmethod
	def build_answer_to_query(frame, query, database):
		if not query.record in database: raise KeyError(f"DNS record {query.record} is not in database: {database}")
		if not query.type in database[query.record]: ValueError(f"DNS record {query.record} is missing the {query.type} type")

		if hasattr(dns, query.type):
			return getattr(dns, query.type)(frame, query, database)

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
	def IDNA(record):
		if type(record) == bytes: record = record.decode('UTF-8')
		return record.encode('idna')

	@abc.abstractmethod
	def extract_queries(DNS_FRAME):#num, data):
		data_pos = 0
		records = OrderedDict()
		for i in range(DNS_FRAME.FRAME_DATA["queries"]["value"]):
			parsed_data_index, record = dns.recurse_record(DNS_FRAME.FRAME_DATA["data"]['bytes'][data_pos:])

			#print(record)
			#b'\x07hvornum\x02se\x00\x00\x06\x00\x01'

			if len(DNS_FRAME.FRAME_DATA["data"]['bytes'][parsed_data_index:parsed_data_index+4]) >= 4:
				query_type = struct.unpack('>H', DNS_FRAME.FRAME_DATA["data"]['bytes'][parsed_data_index:parsed_data_index+2])[0]
				parsed_data_index += 2
				query_class = struct.unpack('>H', DNS_FRAME.FRAME_DATA["data"]['bytes'][parsed_data_index:parsed_data_index+2])[0]
				parsed_data_index += 2

				## We encode each record with the IDNA standard, to support non-ascii domain names like "hehö.se"
				records[dns.IDNA(record[:-1])] = QUERY(DNS_FRAME, query_type=dns.human_query_type(query_type), record=dns.IDNA(record[:-1]), query_class=query_class)
				data_pos += parsed_data_index
			else:
				raise IncompleteFrame(f"There's not enough data to unpack in queries.")
		DNS_FRAME.remainer = DNS_FRAME.FRAME_DATA["data"]['bytes'][data_pos:]
		return records

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

	@abc.abstractmethod
	def email(mail):
		recipient, domain = mail.split('@', 1)
		return dns.pointer(domain, prepend=dns.string(recipient)[:-1]) # the DNS string in a mail record does not end with \x00, so we need to remove it.

	@abc.abstractmethod
	def pointer(record, prepend=b'', tail=b''):
		return POINTER(record, prepend, tail)

class DNS_FIELDS(OrderedDict):
	def __init__(self, *args, **kwargs):
		OrderedDict.__init__(self, *args, **kwargs)

	def __len__(self):
		total = 0
		for key, val in self.items():
			total += len(val)
		return total

	def build(self, header_length, previous_block):
		data = b''
		for val in self.values():
			if type(val) == POINTER: val = val.resolve(header_length, previous_block)
			if type(val) == DNS_FIELDS: val = val.build(header_length, previous_block)
			data += val
		return data

class FINISHED_FRAME():
	def __init__(self, data):
		self.data = data

class BLOCK():
	def __init__(self, FRAME, previous_block=None):
		self.built = False
		self.data = set()
		self._pointers = OrderedDict()
		self.FRAME = FRAME
		self.previous_block = previous_block

	def __len__(self):
		return len(self.data)

	def __gt__(self, what):
		return len(self.data) > what

	def __iadd__(self, obj):
		self.data |= {obj}
		return self

	def __add__(self, obj):
		if not self.built:
			self.built = self.build(None)
		self.built += obj.build(self.built)

		return self

	def __ior__(self, obj):
		"""
		Called when doing |=  operations.
		__or__ and __ror__ for |, __ior__ for |= if you need that specifically.   //FarmArt @ Disco Py
		"""
		return self

	def build(self, previous_block):
		build = b''
		for part in self.data:
			if hasattr(part, 'build'):
				build += part.build(previous_block)
			else:
				build += part.bytes
		return build

		#return self.bytes

	@property
	def pointers(self):
		return self._pointers

	@property
	def bytes(self):
		if self.built:
			return self.built

		final_frame = b''
		for part in self.data:
			final_frame += part.bytes
		return final_frame


class RAW_FIELD():
	def __init__(self, data:bytes):
		self._data = data

class DNS_FIELD():
	def __init__(self, FRAME, data):
		self.FRAME = FRAME
		self.data = data
	def build(self, previous_block):
		if type(self.data) == RAW_FIELD: return self.data._data

		data = b''
		for val in self.data.values():
			if type(val) == POINTER: val = val.resolve(self.FRAME.response.header_length, previous_block)
			if type(val) == DNS_FIELDS: val = val.build(self.FRAME.response.header_length, previous_block)
			data += val
		return data

class ADDITIONAL(DNS_FIELD):
	def __repr__(self):
		return f"<ADDITIONAL BLOCK({len(self.data)})>"

class ANSWER(DNS_FIELD):
	def __repr__(self):
		return f"<ANSWER BLOCK({len(self.data)})>"

class ANSWERS(BLOCK):
	def __repr__(self):
		return f"<ANSWERS BLOCK({len(self.data)})>"

class ADDITIONALS(BLOCK):
	def __repr__(self):
		return f"<ADDITIONALS BLOCK({len(self.data)})>"

class QUERIES(BLOCK):
	def __repr__(self):
		return f"<QUERIES BLOCK({len(self.data)})>"

class DNS_RESPONSE():
	def __init__(self, DNS_FRAME, header_length):
		self.DNS_FRAME = DNS_FRAME
		self.header_length = header_length
		self._queries = QUERIES(self.DNS_FRAME)
		self._answers = ANSWERS(self.DNS_FRAME, self.queries)
		self._authorities = set()
		self._additionals = ADDITIONALS(self.DNS_FRAME, self.answers)

	def __gt__(self, what):
		return self._answers > what

	def __ior__(self, obj):
		"""
		Called when doing |=  operations.
		__or__ and __ror__ for |, __ior__ for |= if you need that specifically.   //FarmArt @ Disco Py
		"""
		if type(obj) == QUERY:
			self._queries += obj
		return self

	def __iadd__(self, obj):
		if type(obj) in (list, tuple, set):
			for item in obj:
				self += item
		elif type(obj) == QUERY:
			self._queries += obj
		elif type(obj) == ANSWER:
			self._answers += obj
		elif type(obj) == ADDITIONAL:
			self._additionals += obj
		else:
			raise ValueError(f'Unknown type trying to be added to {self}: {obj} ({type(obj)})')
		
		return self

	@property
	def queries(self):
		return self._queries

	@property
	def answers(self):
		return self._answers

	@property
	def additionals(self):
		return self._additionals

	@property
	def authorities(self):
		return self._authorities

	@property
	def assemble(self):
		return self._queries + self._answers + self._additionals

class POINTER():
	"""
	Pointers is a pretty simple data struct.
	The problem is that we need to resolve the pointers as the answers are being built.

	To do this, we'll store the reference in `self.record`, and once we call `.resolve()`.
	The POINTER will then look through the currently-being-built-response for a reference
	so the `.record` value. If found, it inserts itself as a pointer - if not, it will simply
	put the record name as-is. That will probably break things tho.

	TODO: Add itself to the additionals section if possible?

	:param record: A string to the record/name we wan't to resolve later
	:type record: str

	:param prepend: Raw bytes to pre-pend the pointer with
	:type prepend: bytes optional

	:param tail: Raw bytes to add after the pointer
	:type tail: bytes optional 
	"""

	## First we point to the position in the query of the name we're resolving.
	## (to avoid appending unessecary data)
	# Pointers:
	#  https://www.freesoft.org/CIE/RFC/1035/43.htm
	#  https://osqa-ask.wireshark.org/questions/50806/help-understanding-dns-packet-data
	
	# 11XXXXXX in binary represents that there's a pointer here in the DNS world.
	# And it has to be exactly 16 bits (2 bytes)
	# self.pointer_pos = sum(self.RAW_FRAME.dns_header_struct)+stream_start
	# self.pointer = struct.pack('>H', int('11' + bin(self.pointer_pos)[2:].zfill(14), 2))
	# self.next_neightbour = self.pointer_pos + stream_length

	def __init__(self, record, prepend=b'', tail=b''):
		self.record = record
		self.prepend = prepend
		self.tail = tail

	def __len__(self):
		return len(self.prepend) + 2 + len(self.tail)

	def resolve(self, header_length, current_frame_build):
		"""
		`resolve` will look through the current frame being built, as well as take the
		header length into account when self-imploading the `.record` into a `bytes` representation
		of the position inside the currently-being-built-frame where the record was found.

		:param header_length: The header length is different in UDP and TCP, there for the length must be known upon resolving.
		:type header_length: int

		:param current_frame_build: Raw `bytes` of an answer being built
		:type current_frame_build: bytes

		:return: A `bytes` representation of the pointer
		:rtype: bytes
		"""
		if (record := dns.string(self.record)) in current_frame_build:
			return self.prepend + struct.pack('>H', int('11' + bin(current_frame_build.find(record)+header_length)[2:].zfill(14), 2)) + self.tail
		return self.prepend + record + self.tail

class QUERY():
	def __init__(self, RAW_FRAME, query_type, record, query_class='IN'):
		if type(query_type) == bytes: query_type = query_type.decode('UTF-8')
		if type(record) == bytes: record = record.decode('UTF-8')
		if type(query_class) == bytes: query_class = query_class.decode('UTF-8')

		self.CLIENT_IDENTITY = RAW_FRAME.CLIENT_IDENTITY
		self.RAW_FRAME = RAW_FRAME
		self.type = query_type
		self.record = record
		self.CLASS = query_class

	@property
	def bytes(self):
		return dns.build_query_field(self)

	def __repr__(self):
		return f"<QUERY record={self.record}, type={self.type}>"

class DNS_TCP_FRAME():
	def __init__(self, CLIENT_IDENTITY):
		self.CLIENT_IDENTITY = CLIENT_IDENTITY
		self.FRAME_DATA = {}

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

		self.remainer = b''
		## given `dns_header_struct`, split the data up into the blocks defined there.
		binary = list(byte_to_bin(self.CLIENT_IDENTITY.buffer, bin_map=self.dns_header_struct))
		self.response = DNS_RESPONSE(self, header_length=sum(self.dns_header_struct))

		## Take each block from `dns_header_struct` and use `dns_header_fields` to create a key: val pair of the two.
		##    We'll split the data into binary, bytes and hex - as we need those different options for later
		##    when we need to for instance create pointers, by merging the binary '11' + bin(target) later as an example.
		for index in range(len(binary)):
			self.FRAME_DATA[self.dns_header_fields[index]] = {'binary' : binary[index], 'bytes' : bin_str_to_byte(binary[index]), 'hex' : None}
			self.FRAME_DATA[self.dns_header_fields[index]]['hex'] = bytes_to_hex(self.FRAME_DATA[self.dns_header_fields[index]]['bytes'])

		## If the query data section isn't exactly two bytes, we haven't gotten enough data to even begin parsing.
		if not len(self.FRAME_DATA["queries"]["bytes"]) == 2:
			yield (Events.CLIENT_NO_QUERIES, None)
			return
		
		self.FRAME_DATA["queries"]["value"] = struct.unpack(">H", self.FRAME_DATA["queries"]["bytes"])[0]
		self.CLIENT_IDENTITY.server.log(f'[+] Got {self.FRAME_DATA["queries"]["value"]} queries from {self.CLIENT_IDENTITY}')

		if self.FRAME_DATA["queries"]["value"] <= 0:
			yield (Events.CLIENT_NO_QUERIES, None)
			return
		
		## Parse the frame header
		for option, value in dns.parse_header_flags(self.FRAME_DATA["flags"]).items():
			self.FRAME_DATA['flags'][option] = value

		## if QR isn't 0, the client is trying something fishy.. or if the 'data' section is short/not there, there's no queries to parse.
		## So we'll send an event up the chain.
		if not self.FRAME_DATA['flags']['QR'] == 0 or 'data' not in self.FRAME_DATA:
			self.CLIENT_IDENTITY.server.log(f'[-] Warning, Malformed data detected: {self.CLIENT_IDENTITY}')
			yield (Events.CLIENT_INVALID_DATA, None)
			return

		#pointers = {}

		#query_block = set()
		#answers = set()
		#additionals = set()
		#authorities = set()

		#print(self.CLIENT_IDENTITY.buffer)
		#print(self.FRAME_DATA)
		try:
			queries = dns.extract_queries(self)#self.FRAME_DATA["queries"]["value"], self.FRAME_DATA["data"])
		except IncompleteFrame as e:
			self.CLIENT_IDENTITY.server.log(f'[*] Warning, Malformed data detected from {self.CLIENT_IDENTITY}: {e}')
			return

		for index, query in enumerate(queries.values()):
			if query.type and query.record in self.CLIENT_IDENTITY.server.database and query.type in self.CLIENT_IDENTITY.server.database[query.record]:
				self.response += query # Add the query to the response (as it's the first block ouf of three (query, answer, additionals))
				self.response += dns.build_answer_to_query(self, query, self.CLIENT_IDENTITY.server.database)

				self.CLIENT_IDENTITY.server.log(f"[ ] Query {index+1}: {query.type}:{query.record} -> {self.CLIENT_IDENTITY.server.database[query.record][query.type]['target']}")
			elif query.record not in self.CLIENT_IDENTITY.server.database:
				self.CLIENT_IDENTITY.server.log(f'[-] DNS record {query.record} is not in database: {self.CLIENT_IDENTITY.server.database.keys()}')
			elif query.type and not query.type in self.CLIENT_IDENTITY.server.database[query.record]:
				self.CLIENT_IDENTITY.server.log(f"[-] DNS record {query.record} is missing a record for {query.type} requests")
			else:
				self.CLIENT_IDENTITY.server.log(f"[-] Record type {query.type} is not implemented (While handling {query.record})")

		if self.FRAME_DATA['additional_resource_records']:
			self.response += ADDITIONAL(self, RAW_FIELD(self.remainer))
		
		#	# wireshark_match = '\\x'+'\\x'.join([hex(i)[2:].zfill(2) for i in self.FRAME_DATA["data"]['bytes'][parsed_data_index:]])
		#	# print(wireshark_match)
		#	self.response += ADDITIONAL(self.FRAME_DATA['data']['bytes'][parsed_data_index:])

		response = self.FRAME_DATA['transaction_id']['bytes']
		response += b'\x85\x00' # Flags  b'\x81\x80'
		response += struct.pack('>H', len(self.response.queries))     # Queries
		response += struct.pack('>H', len(self.response.answers))     # answer rrs
		response += struct.pack('>H', len(self.response.authorities)) # authority rrs
		response += struct.pack('>H', len(self.response.additionals)) # additional records
		response += self.response.assemble.bytes

		response = self.finalize_response(response)

		#if len(answers) > 0:
		#	self.socket.sendto(response, addr)

		if self.response > 0:
			yield (Events.CLIENT_RESPONSE_DATA, response)

class DNS_UDP_FRAME(DNS_TCP_FRAME):
	## Larger UDP frames: "Permitting Larger DNS UDP Packets" @:
	##   https://tools.ietf.org/html/draft-ietf-dnsind-udp-size-02
	def __init__(self, CLIENT_IDENTITY):
		self.CLIENT_IDENTITY = CLIENT_IDENTITY
		self.FRAME_DATA = {}

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