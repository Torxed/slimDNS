import dataclasses

class Interface(object):
	def __init__(self, name):
		self.name = name

	def __call__(self, value):
		print(value)
		return value

@dataclasses.dataclass
class DNSHeaders:
	transaction_id :bytes
	flags :list
	queries :int
	answers_resource_records :int
	authorities_resource_records :int
	additional_resource_records :int