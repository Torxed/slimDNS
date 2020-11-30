import abc, struct, ipaddress
from collections import OrderedDict

from .exceptions import *

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
			'ptr' : 12,
			'mx' : 15,
			'txt' : 16,
			'aaaa' : 28,
			'srv' : 33,
			'opt' : 41,
			'spf' : 99,
			'caa' : 257
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
			12 : 'PTR',
			15 : 'MX',
			16 : 'TXT',
			28 : 'AAAA',
			33 : 'SRV',
			41 : 'OPT',
			99 : 'SPF',
			257 : 'CAA'
		}
		if not i or i not in types:
			if i:
				print(f'[!] Unknown record query type: {i}')
			return None
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
		record = dns.string(query.record.lower())

		#      record | type | class
		return record + struct.pack('>H', dns.record_type(query.type)) + b'\x00\x01'

	@abc.abstractmethod
	def translate(frame, query, target):
		from .data import QUERY

		if QUERY(frame, query.type, query.record.lower()) in frame.response.queries:
			return dns.pointer(target)
		else:
			return dns.string(target)

	@abc.abstractmethod
	def AAAA(frame, query, database):
		from .data import NONE_ANSWER

		frame.response.flags = b'\x81\x05'
		return NONE_ANSWER(None, None)

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

		from .data import ANSWER, DNS_FIELDS
		from .utilities import ip_to_bytes

		ip = ip_to_bytes(ipaddress.ip_address(database[query.record.lower()][query.type]['target']))

		return ANSWER(frame, DNS_FIELDS({
			'record_name' : dns.pointer(query.record.lower()),
			'record_type' : struct.pack('>H', dns.record_type('A')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record.lower()][query.type]['ttl']),
			'length' : struct.pack('>H', len(ip)),

			'data' : ip
		}))

	@abc.abstractmethod
	def SOA(frame, query, database):
		from .data import ANSWER, DNS_FIELDS

		SOA_specifics = DNS_FIELDS({
			'primary_server' : dns.string(database[query.record.lower()][query.type]['target']), #dns.translate(frame, query, database[query.record.lower()][query.type]['target']),
			'mailbox' : dns.email(f'root@{query.record.lower()}'),
			'serial_number' : struct.pack('>i', 2020100801),
			'refresh_interval' : struct.pack('>i', 360),
			'retry_interval' : struct.pack('>i', 360),
			'expire_limit' : struct.pack('>i', 360),
			'ninimum_ttl' : struct.pack('>i', 360)
		})

		return ANSWER(frame, DNS_FIELDS({
			'domain_name' : dns.pointer(query.record.lower()),

			'record_type' : struct.pack('>H', dns.record_type('SOA')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record.lower()][query.type]['ttl']),
			'length' : struct.pack('>H', len(SOA_specifics)),

			'data' : SOA_specifics
		}))

	@abc.abstractmethod
	def CAA(frame, query, database):
		from .data import AUTHORITY, DNS_FIELDS

		server = dns.pointer(query.record)
		if query.record.lower() != database[query.record.lower()]['CAA']['target']:
			server = dns.string(database[query.record.lower()]['CAA']['target'])

		CAA_SPECIFICS = DNS_FIELDS({
			'primary_server' : server,
			'mailbox' : dns.email(f'root@{query.record.lower()}'),
			'serial_number' : struct.pack('>i', 2020100801),
			'refresh_interval' : struct.pack('>i', 360),
			'retry_interval' : struct.pack('>i', 360),
			'expire_limit' : struct.pack('>i', 360),
			'ninimum_ttl' : struct.pack('>i', 360)
		})

		frame.response.flags = b'\x81\x80'
		return AUTHORITY(frame, DNS_FIELDS({
			'domain_name' : dns.pointer(query.record),

			'record_type' : struct.pack('>H', dns.record_type('SOA')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record.lower()][query.type]['ttl']),
			'length' : struct.pack('>H', len(CAA_SPECIFICS)),

			'data' : CAA_SPECIFICS
		}))

	@abc.abstractmethod
	def MX(frame, query, database):
		from .data import ANSWER, DNS_FIELDS

		# First, wrap single-targets into a list
		# So that we can handle list objects (if multiple records are allowed)
		# TODO: Perhaps move this check into earlier stages?
		mx_servers = database[query.record.lower()][query.type]
		if not type(mx_servers) in (list, tuple):
			mx_servers = [mx_servers]

		answer_frame = []
		for mx_target in mx_servers:


			MX_specifics = DNS_FIELDS({
				'preference' : struct.pack('>H', mx_target['priority']),
				'mail_exchange' : dns.string(mx_target['target']),
			})

			answer_frame.append(ANSWER(frame, DNS_FIELDS({
				'domain_name' : dns.pointer(query.record.lower()),

				'record_type' : struct.pack('>H', dns.record_type('MX')),
				'class' : struct.pack('>H', dns.record_class('IN')),
				'ttl' : struct.pack('>I', mx_target['ttl']),
				'length' : struct.pack('>H', len(MX_specifics)),

				'data' : MX_specifics
			})))

		return answer_frame

	@abc.abstractmethod
	def NS(frame, query, database):
		from .data import ANSWER, ADDITIONAL
		from .utilities import ip_to_bytes

		# First, wrap single-targets into a list
		# So that we can handle list objects (if multiple records are allowed)
		# TODO: Perhaps move this check into earlier stages?
		ns_servers = database[query.record.lower()][query.type]
		if not type(ns_servers) in (list, tuple):
			ns_servers = [ns_servers]

		answer_frame = []
		additional_data = []

		for ns_target in ns_servers:
			answer_frame.append(ANSWER(frame, {
				'pointer' : dns.pointer(query.record.lower()),
				'record_type' : struct.pack('>H', dns.record_type('NS')),
				'class' : struct.pack('>H', dns.record_class('IN')),
				'ttl' : struct.pack('>I', ns_target['ttl']),
				'length' : struct.pack('>H', len(dns.string(ns_target['target']))),
				'name_server' : dns.string(ns_target['target'])
			}))

			additional_data.append(ADDITIONAL(frame, {
				'pointer' : dns.pointer(ns_target['target']), # Pointers gets resolved at build time, and can be safely stored as a standalone record.
				'type' : struct.pack('>H', dns.record_type('A')),
				'class' : struct.pack('>H', dns.record_class('in')),
				'ttl' : struct.pack('>i', 60),
				'length' : struct.pack('>H', 4),
				'data' : ip_to_bytes(ipaddress.ip_address(database[ns_target['target']]['A']['target']))
			}))

		return [*answer_frame, *additional_data]

	@abc.abstractmethod
	def SRV(frame, query, database):
		from .data import ANSWER, ADDITIONAL
		from .utilities import ip_to_bytes

		srv_target = database[query.record.lower()][query.type]['target']

		answer_data = b''.join(OrderedDict({
			'priority' : struct.pack('>H', database[query.record.lower()][query.type]['priority']),
			'weight' : b'\x00\x00',
			'port' : struct.pack('>H', database[query.record.lower()][query.type]['port']),
			'target' : dns.string(bytes(srv_target, 'UTF-8'))
		}).values())
		
		return ANSWER(frame, {
			'pointer' : dns.pointer(query.record.lower()),
			'record_type' : struct.pack('>H', dns.record_type('SRV')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record.lower()][query.type]['ttl']),
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
	def TXT(frame, query, database):
		from .data import ANSWER, DNS_FIELDS

		MX_specifics = DNS_FIELDS({
			'txt_content' : dns.string(database[query.record.lower()][query.type]['target']),
		})

		return ANSWER(frame, DNS_FIELDS({
			'domain_name' : dns.pointer(query.record.lower()),

			'record_type' : struct.pack('>H', dns.record_type('TXT')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record.lower()][query.type]['ttl']),
			'length' : struct.pack('>H', len(MX_specifics)),

			'data' : MX_specifics
		}))

	@abc.abstractmethod
	def SPF(frame, query, database):
		from .data import ANSWER, DNS_FIELDS

		SOA_specifics = DNS_FIELDS({
			'primary_server' : dns.pointer(database[query.record.lower()][query.type]['target']),
			'mailbox' : dns.email(f'root@{query.record.lower()}'),
			'serial_number' : struct.pack('>i', 2020100801),
			'refresh_interval' : struct.pack('>i', 360),
			'retry_interval' : struct.pack('>i', 360),
			'expire_limit' : struct.pack('>i', 360),
			'ninimum_ttl' : struct.pack('>i', 360)
		})

		return ANSWER(frame, DNS_FIELDS({
			'domain_name' : dns.pointer(query.record.lower()),

			'record_type' : struct.pack('>H', dns.record_type('SOA')),
			'class' : struct.pack('>H', dns.record_class('IN')),
			'ttl' : struct.pack('>I', database[query.record.lower()][query.type]['ttl']),
			'length' : struct.pack('>H', len(SOA_specifics)),

			'data' : SOA_specifics
		}))

	@abc.abstractmethod
	def PTR(frame, query, database):
		from .data import NONE_ANSWER

		frame.response.flags = b'\x81\x05'
		return NONE_ANSWER(None, None)

	@abc.abstractmethod
	def OPT(frame, query, database):
		from .data import ADDITIONAL, DNS_FIELDS

		"""
		The OPT field is added to the additional section.
		But only if support for certain things are available, like EDNS.

		RDATA:
		   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		0: |                          OPTION-CODE                          |
		   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		2: |                         OPTION-LENGTH                         |
		   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		4: |                                                               |
		   /                          OPTION-DATA                          /
		   /                                                               /
		   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		"""

# Cookie data:
#		OPTION_DATA = b'\x26\x7f\x84\xb9\x0a\x66\x3e\x4f'

#		RDATA = DNS_FIELDS({
#			'option code' : struct.pack('>H', 10), # Cookie
#			'option length' : struct.pack('>H', len(OPTION_DATA))
#			'option data' : OPTION_DATA
#		})
		RDATA = b''

		return ADDITIONAL(frame, DNS_FIELDS({
				'name' : struct.pack('B', 0), # Always zero, meaning "root"
				'type' : struct.pack('>H', dns.record_type('OPT')),
				'UDP payload size' : struct.pack('>H', 4096), # 8192?
				'RCODE' : struct.pack('B', 0),
				'EDNS0 version' : struct.pack('B', 0),
				'DO bit' : struct.pack('>H', 0), # First bit in the two bytes = DO bit, 0 DO bit = no DNSSEC, reset is reserved
				'Data Length' : struct.pack('>H', len(RDATA)),
				#'RDATA' : RDATA
			}))

	@abc.abstractmethod
	def build_answer_to_query(frame, query, database):
		if not query.record.lower() in database: raise KeyError(f"DNS record {query.record.lower()} is not in database: {database}")
		if not query.type in database[query.record.lower()]: ValueError(f"DNS record {query.record.lower()} is missing the {query.type} type")

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
		from .data import QUERY

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
		from .data import POINTER

		return POINTER(record, prepend, tail)