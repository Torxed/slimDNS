import dataclasses

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
	flags :list
	queries :int
	answers_resource_records :int
	authorities_resource_records :int
	additional_resource_records :int

@dataclasses.dataclass
class DNSRequest:
	headers :DNSHeaders
	raw_data :bytes
	addressing :AddressInfo
