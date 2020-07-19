from .exceptions import *
from .servers import *

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