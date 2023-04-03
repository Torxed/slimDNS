import os
import errno
import hashlib
import struct

def unique_identifier(rnd_len=12, algo=hashlib.md5):
	return algo(os.urandom(rnd_len)).hexdigest()


def pid_exists(pid):
	"""Check whether pid exists in the current process table.
	UNIX only.
	"""
	if pid < 0:
		return False
	if pid == 0:
		# According to "man 2 kill" PID 0 refers to every process
		# in the process group of the calling process.
		# On certain systems 0 is a valid PID but we have no way
		# to know that in a portable fashion.
		raise ValueError('invalid PID 0')
	try:
		os.kill(pid, 0)
	except OSError as err:
		if err.errno == errno.ESRCH:
			# ESRCH == No such process
			return False
		elif err.errno == errno.EPERM:
			# EPERM clearly means there's a process to deny access to
			return True
		else:
			# According to "man 2 kill" possible error values are
			# (EINVAL, EPERM, ESRCH)
			raise
	else:
		return True

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