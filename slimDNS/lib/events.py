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