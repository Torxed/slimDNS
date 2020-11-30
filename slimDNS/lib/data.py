import struct
from collections import OrderedDict

from .exceptions import *
from .abstracts import dns
from .events import *

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

	def __contains__(self, item):
		for data_object in self.data:
			if type(item) == type(data_object) and item.record == data_object.record and item.type == data_object.type:
				return True
		return False

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

class AUTHORITY(DNS_FIELD):
	def __repr__(self):
		return f"<AUTHORITY BLOCK({len(self.data)})>"

class AUTHORITIES(BLOCK):
	def __repr__(self):
		return f"<AUTHORITIES BLOCK({len(self.data)})>"

class ADDITIONALS(BLOCK):
	def __repr__(self):
		return f"<ADDITIONALS BLOCK({len(self.data)})>"

class QUERIES(BLOCK):
	def __repr__(self):
		return f"<QUERIES BLOCK({len(self.data)})>"

class NONE_ANSWER(BLOCK):
	def __repr__(self):
		return f"<NONE_ANSWER>"

class DNS_RESPONSE():
	def __init__(self, DNS_FRAME, header_length):
		self.DNS_FRAME = DNS_FRAME
		self.header_length = header_length
		self._flags = b'\x85\x00'
		#self._flags = b'\x81\x80'
		self._queries = QUERIES(self.DNS_FRAME)
		self._answers = ANSWERS(self.DNS_FRAME, self.queries)
		self._authorities = AUTHORITIES(self.DNS_FRAME, self.answers)
		self._additionals = ADDITIONALS(self.DNS_FRAME, self.authorities)

	@property
	def flags(self):
		return self._flags
	
	@flags.setter
	def flags(self, value):
		self._Flags = value

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
		"""
		When doing `+=` on a `DNS_RESPONSE`, it will automatically attempt to detect
		if the value being added is a :class:`~slimDNS.QUERY`, :class:`~slimDNS.ANSWER` or :class:`~slimDNS.ADDITIONAL`. And place the data in
		the appropraite container. This makes for a smoother use case where the developer
		can add anything in any order and any ammount of data without having to worry
		where to place them. As long as the data type being added is one of the three,
		either one by one or data in a `(list, tuple, set)`.
		"""
		if type(obj) in (list, tuple, set):
			for item in obj:
				self += item
		elif type(obj) == QUERY:
			self._queries += obj
		elif type(obj) == ANSWER:
			self._answers += obj
		elif type(obj) == AUTHORITY:
			self._authorities += obj
		elif type(obj) == ADDITIONAL:
			self._additionals += obj
		elif type(obj) == NONE_ANSWER:
			pass # A non-response
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
		return self._queries + self._answers + self._authorities + self._additionals

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
		self.header_length = sum(self.dns_header_struct)-2 # Offsets are counted from the Transaction ID, and does not include the 2 bytes of "Length"

	def finalize_response(self, response):
		return struct.pack('>H', len(response)) + response

	def parse(self):
		from .utilities import byte_to_bin, bin_str_to_byte, bytes_to_hex
		# data, addr = self.socket.recvfrom(8192)

		self.remainer = b''
		## given `dns_header_struct`, split the data up into the blocks defined there.
		binary = list(byte_to_bin(self.CLIENT_IDENTITY.buffer, bin_map=self.dns_header_struct))
		self.response = DNS_RESPONSE(self, header_length=self.header_length)

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
		# self.CLIENT_IDENTITY.server.log(f'[+] Got {self.FRAME_DATA["queries"]["value"]} queries from {self.CLIENT_IDENTITY}')

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

		try:
			queries = dns.extract_queries(self)#self.FRAME_DATA["queries"]["value"], self.FRAME_DATA["data"])
		except IncompleteFrame as e:
			self.CLIENT_IDENTITY.server.log(f'[*] Warning, Malformed data detected from {self.CLIENT_IDENTITY}: {e}')
			return

		for index, query in enumerate(queries.values()):
			if query.type and query.record.lower() in self.CLIENT_IDENTITY.server.database and query.type in self.CLIENT_IDENTITY.server.database[query.record.lower()]:
				self.response += query # Add the query to the response (as it's the first block ouf of three (query, answer, additionals))
				self.response += dns.build_answer_to_query(self, query, self.CLIENT_IDENTITY.server.database)

				self.CLIENT_IDENTITY.server.log(f"[ ] Query {index+1}: {query.type}:{query.record.lower()} -> {self.CLIENT_IDENTITY.server.database[query.record.lower()][query.type]}")
			elif query.record.lower() not in self.CLIENT_IDENTITY.server.database:
				pass # self.CLIENT_IDENTITY.server.log(f'[-] DNS record {query.record.lower()} is not in database: {self.CLIENT_IDENTITY.server.database.keys()}')
			elif query.type and not query.type in self.CLIENT_IDENTITY.server.database[query.record.lower()]:
				pass #self.CLIENT_IDENTITY.server.log(f"[-] DNS record {query.record.lower()} is missing a record for {query.type} requests")
			elif query.type:
				self.CLIENT_IDENTITY.server.log(f"[-] Record type {query.type} is not implemented (While handling {query.record.lower()})")

		if self.FRAME_DATA['additional_resource_records']:
			self.response += dns.OPT(self, query, self.CLIENT_IDENTITY.server.database)
		#	print("There's additional resource records for this query. Appending!")
		#	self.response += ADDITIONAL(self, RAW_FIELD(self.remainer))
		
		#	# wireshark_match = '\\x'+'\\x'.join([hex(i)[2:].zfill(2) for i in self.FRAME_DATA["data"]['bytes'][parsed_data_index:]])
		#	# print(wireshark_match)
		#	self.response += ADDITIONAL(self.FRAME_DATA['data']['bytes'][parsed_data_index:])

		response = self.FRAME_DATA['transaction_id']['bytes']
		response += self.response.flags
		response += struct.pack('>H', len(self.response.queries))     # Queries
		response += struct.pack('>H', len(self.response.answers))     # answer rrs
		response += struct.pack('>H', len(self.response.authorities)) # authority rrs
		response += struct.pack('>H', len(self.response.additionals)) # additional records
		response += self.response.assemble.bytes

		response = self.finalize_response(response)

		if self.response > 0 or self.response.flags in (b'\x81\x05', b'\x81\x80', b'\x85\x00'): # TODO: Ugly hack of checking if the flag "Reply code: refused" is set, which causes an empty response and should be sent anyway.
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
		self.header_length = sum(self.dns_header_struct)

	def finalize_response(self, response):
		# UDP doesn't require any additional lengths etc.
		return response