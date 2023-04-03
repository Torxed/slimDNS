import dataclasses
import struct
from .logger import log
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
class DNSRequest:
	headers :DNSHeaders
	raw_data :bytes
	addressing :AddressInfo

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

	def post_processing(self):
		data_pos = 0
		records = []
		for i in range(self.headers.queries):
			parsed_data_index, record = self.recursive_lookup(self.raw_data[data_pos:])

			#print(record)
			#b'\x07hvornum\x02se\x00\x00\x06\x00\x01'

			if len(self.raw_data[parsed_data_index:parsed_data_index+4]) >= 4:
				query_type = struct.unpack('>H', self.raw_data[parsed_data_index:parsed_data_index+2])[0]
				parsed_data_index += 2
				query_class = struct.unpack('>H', self.raw_data[parsed_data_index:parsed_data_index+2])[0]
				parsed_data_index += 2

				## We encode each record with the IDNA standard, to support non-ascii domain names like "hehö.se"
				records.append(QUERY(query_type=human_query_type(query_type), record=IDNA(record[:-1]), query_class=query_class))
				data_pos += parsed_data_index
			else:
				raise IncompleteFrame(f"There's not enough data to unpack in queries.")

		# DNS_FRAME.remainer = self.raw_data[data_pos:]
		return records

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
	def from_request(dns_request):
#		log.info(f"DNSQueries: {dns_request}")
		
		return DNSQueries(queries=dns_request.post_processing())

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
	def from_queries(dns_queries):
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
class DNSAdditionals:
	request: DNSRequest

	@property
	def bytes(self):
		if self.request.headers.additional_resource_records:
			return (
				b'\x00' # Name: <root>
				+ b'\x00\x29' # Type: OPT (41)
				+ b'\x04\xd0' # UDP payload size: 1232
				+ b'\x00' # Higher bits in extended RCODE
				+ b'\x00' # EDNS0 version: 0
				+ b'\x00\x00' # Z: 0x0000
				+ b'\x00\x00' # Data length: 0
			)

	def __len__(self):
		return self.request.headers.additional_resource_records


	def __radd__(self, authorities):
		if type(authorities) != bytes:
			raise TypeError(f"obj + DNSAdditionals() - obj needs to be DNSAuthorities().bytes")

		return authorities + self.bytes

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