import dataclasses
import struct
from .logger import log
from .exceptions import IncompleteFrame
from .dns import IDNA, human_query_type, record_type, string


class Interface(object):
	def __init__(self, name):
		self.name = name

	def __call__(self, value):
		print(value)
		return value


@dataclasses.dataclass
class AbstractLayerAddressing:
	source :str
	destination :str


@dataclasses.dataclass
class Layer2(AbstractLayerAddressing):
	pass


@dataclasses.dataclass
class Layer3(AbstractLayerAddressing):
	pass


@dataclasses.dataclass
class Layer4:
	source :int
	destination :int


@dataclasses.dataclass
class AddressInfo:
	layer2 :Layer2
	layer3 :Layer3
	layer4 :Layer4
	

@dataclasses.dataclass
class DNSHeaders:
	transaction_id :bytes
	flags :dict
	queries :int
	answers_resource_records :int
	authorities_resource_records :int
	additional_resource_records :int


@dataclasses.dataclass
class QUERY:
	query_type :str
	record :str
	query_class :str


@dataclasses.dataclass
class DNSQueries:
	queries :list

	@property
	def bytes(self):
		data = b''
		for query in self.queries:
			data += string(query.record.lower()) + struct.pack('>H', record_type(query.query_type)) + b'\x00\x01'

		return data

	def __len__(self):
		return len(self.queries)

	def __radd__(self, obj):
		raise TypeError(f"DNSQueries() and not be added on the right side of {obj}")

	@staticmethod
	def from_request(dns_request, worker=None):
#		log.info(f"DNSQueries: {dns_request}")

		data_pos = 0
		records = []
		for i in range(dns_request.headers.queries):
			parsed_data_index, record = dns_request.recursive_lookup(dns_request.raw_data[data_pos:])

			#print(record)
			#b'\x07hvornum\x02se\x00\x00\x06\x00\x01'

			if len(dns_request.raw_data[parsed_data_index:parsed_data_index+4]) >= 4:
				query_type = struct.unpack('>H', dns_request.raw_data[parsed_data_index:parsed_data_index+2])[0]
				parsed_data_index += 2
				query_class = struct.unpack('>H', dns_request.raw_data[parsed_data_index:parsed_data_index+2])[0]
				parsed_data_index += 2

				## We encode each record with the IDNA standard, to support non-ascii domain names like "hehö.se"
				records.append(QUERY(query_type=human_query_type(query_type), record=IDNA(record[:-1]), query_class=query_class))
				data_pos += parsed_data_index
			else:
				raise IncompleteFrame(f"There's not enough data to unpack in queries.")
		
		dns_request.raw_data = dns_request.raw_data[data_pos:]
		dns_request.queries = DNSQueries(queries=records)
		return dns_request.queries


@dataclasses.dataclass
class DNSAnswers:
	@property
	def bytes(self):
		return b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + b'\x2e\x15\x66\x51'

	def __len__(self):
		return 1

	def __radd__(self, queries):
		if type(queries) != DNSQueries:
			raise TypeError(f"obj + DNSAnswers() - obj needs to be DNSQueries")

		return queries.bytes + self.bytes

	@staticmethod
	def from_queries(dns_queries, worker=None):
		return DNSAnswers()


@dataclasses.dataclass
class DNSAuthorities:
	@property
	def bytes(self):
		return b''

	def __len__(self):
		return 0

	def __radd__(self, answers):
		if type(answers) != bytes:
			raise TypeError(f"obj + DNSAuthorities() - obj needs to be DNSAnswers().bytes not {type(answers)}")

		return answers + self.bytes


@dataclasses.dataclass
class OPT:
	name :str | None = None
	record_type :int = 41
	udp_payload_size :int = 1232
	higher_bits_in_extended_rcode :int = 0
	EDNS0_version :int = 0
	Z : int = 0
	data_length :int = 0
	option_data :bytes | None = None


@dataclasses.dataclass
class DNSAdditionals:
	records :list

	@property
	def bytes(self):
		#if self.request.headers.additional_resource_records:
		result = b''
		for record in self.records:
			result += (
				b'\x00' # Name: <root>
				+ struct.pack('>H', record.record_type) # Type: OPT (41)
				+ struct.pack('>H', record.udp_payload_size) # UDP payload size: 1232
				+ b'\x00' # Higher bits in extended RCODE
				+ b'\x00' # EDNS0 version: 0
				+ b'\x00\x00' # Z: 0x0000
				+ b'\x00\x00' # Data length: 0
			)

		return result

	def __len__(self):
		return len(self.records)#self.request.headers.additional_resource_records


	def __radd__(self, authorities):
		if type(authorities) != bytes:
			raise TypeError(f"obj + DNSAdditionals() - obj needs to be DNSAuthorities().bytes")

		return authorities + self.bytes

	@staticmethod
	def from_request(dns_request, worker=None):
		data_pos = 0
		records = []
		worker.log(f"AAD: {dns_request.headers.additional_resource_records} on {dns_request.raw_data}");
		for i in range(dns_request.headers.additional_resource_records):
			if not struct.unpack('B', dns_request.raw_data[0:1])[0]:
				name = 'root'
			else:
				raise NotImplemented(f"No idea how to deal with non-root packages")

			if name == 'root':
				record_type = struct.unpack('>H', dns_request.raw_data[1:3])[0]
				udp_payload_size = struct.unpack('>H', dns_request.raw_data[3:5])[0]
				higher_bits_in_extended_rcode = record_type = struct.unpack('B', dns_request.raw_data[5:6])[0]
				EDNS0_version = struct.unpack('B', dns_request.raw_data[6:7])[0]
				Z = struct.unpack('>H', dns_request.raw_data[7:9])[0]
				data_length = struct.unpack('>H', dns_request.raw_data[9:11])[0]

				option_data = dns_request.raw_data[11:11+data_length]

				records.append(OPT(
					name=None,
					record_type=record_type,
					udp_payload_size=udp_payload_size,
					higher_bits_in_extended_rcode=higher_bits_in_extended_rcode,
					EDNS0_version=EDNS0_version,
					Z=Z,
					data_length=0,
					option_data=None
				))

			print(f"Should really implement option_data handling: {option_data}")

		# 	parsed_data_index, record = dns_request.recursive_lookup(dns_request.raw_data[data_pos:])

		# 	#print(record)
		# 	#b'\x07hvornum\x02se\x00\x00\x06\x00\x01'

		# 	if len(dns_request.raw_data[parsed_data_index:parsed_data_index+4]) >= 4:
		# 		query_type = struct.unpack('>H', dns_request.raw_data[parsed_data_index:parsed_data_index+2])[0]
		# 		parsed_data_index += 2
		# 		query_class = struct.unpack('>H', dns_request.raw_data[parsed_data_index:parsed_data_index+2])[0]
		# 		parsed_data_index += 2

		# 		## We encode each record with the IDNA standard, to support non-ascii domain names like "hehö.se"
		# 		records.append(QUERY(query_type=human_query_type(query_type), record=IDNA(record[:-1]), query_class=query_class))
		# 		data_pos += parsed_data_index
		# 	else:
		# 		raise IncompleteFrame(f"There's not enough data to unpack in queries.")
		
		# dns_request.queries = DNSQueries(queries=records)
		# return dns_request.queries
		
		return DNSAdditionals(records=records)


@dataclasses.dataclass
class DNSRequest:
	headers :DNSHeaders
	raw_data :bytes
	addressing :AddressInfo

	queries :DNSQueries | None = None
	additionals :DNSAdditionals | None = None

	def recursive_lookup(self, d, data_pos=0, recursed=0):
		if len(d) <= 0: return 0, b''

		query = b''
		query_length = d[0]
		query += d[1:1+query_length]
		parsed_data = 1+query_length

		if query_length == 0 or recursed == 255: # Maximum recursion depth
			return parsed_data, query
		else:
			recused_parsed_data, recursed_query = self.recursive_lookup(d[parsed_data:], data_pos=data_pos, recursed=recursed)
			return parsed_data+recused_parsed_data, query + b'.' + recursed_query


@dataclasses.dataclass
class DNSResponse:
	transaction_id :bytes
	flags :bytes
	queries :bytes
	answers :bytes
	authorities :bytes
	additionals :bytes
	data :bytes

	@property
	def bytes(self):
		return b''.join([getattr(self, field.name) for field in dataclasses.fields(DNSResponse) if field.type == bytes])