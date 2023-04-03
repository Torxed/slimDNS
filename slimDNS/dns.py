import struct

def IDNA(record):
	if type(record) == bytes: record = record.decode('UTF-8')
	return record.encode('idna')

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
		# if i:
		# 	print(f'[!] Unknown record query type: {i}')
		return None
	return types[i]

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