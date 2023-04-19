import ctypes
import fcntl
import ipaddress
import select
import socket
import struct
import zlib
import binascii
import traceback
import random
import time
import dataclasses

from ..argparsing import args
from ..logger import log
from ..helpers import _DNS_HEADER_STRUCT, byte_to_bin, bin_str_to_byte, bytes_to_hex
from ..types import DNSHeaders, DNSRequest, AddressInfo, Layer2, Layer3, Layer4

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_AUXDATA = 8

class tpacket_auxdata(ctypes.Structure):
	_fields_ = [
		("tp_status", ctypes.c_uint),
		("tp_len", ctypes.c_uint),
		("tp_snaplen", ctypes.c_uint),
		("tp_mac", ctypes.c_ushort),
		("tp_net", ctypes.c_ushort),
		("tp_vlan_tci", ctypes.c_ushort),
		("tp_padding", ctypes.c_ushort),
	]

# This is a ctype structure that matches the
# requirements to set a socket in promisc mode.
# In all honesty don't know where i found the values :)
class ifreq(ctypes.Structure):
	_fields_ = [("ifr_ifrn", ctypes.c_char * 16),
				("ifr_flags", ctypes.c_short)]

class promisc():
	IFF_PROMISC = 0x100
	SIOCGIFFLAGS = 0x8913
	SIOCSIFFLAGS = 0x8914

	def __init__(self, s, interface=b'ens33'):
		self.s = s
		self.fileno = s.fileno()
		self.interface = interface
		self.ifr = ifreq()

	def on(self):
		# -- Set up promisc mode:

		self.ifr.ifr_ifrn = self.interface

		fcntl.ioctl(self.fileno, self.SIOCGIFFLAGS, self.ifr)
		self.ifr.ifr_flags |= self.IFF_PROMISC

		fcntl.ioctl(self.fileno, self.SIOCSIFFLAGS, self.ifr)
		# ------------- DONE

	def off(self):
		# Turn promisc mode off:
		self.ifr.ifr_flags &= ~self.IFF_PROMISC
		fcntl.ioctl(self.fileno, self.SIOCSIFFLAGS, self.ifr)
		# ------------- DONE

def binToObj(b, func):
	""" takes a bytes() string and calls func() on each int() value of the bytes() string """
	return [func(i) for i in b]

def ip_to_bytes(addr):
	if addr == '':
		return b''

	addr = b''
	for block in str(addr).split('.'):
		addr += struct.pack('B', block)

	return addr

def bytes_to_ip(b):
	s = ''
	for i in b:
		s += '{:d}.'.format(i) # Int -> INT.
	return ipaddress.ip_address(s[:-1])

def bytes_to_mac(obj):
	if type(obj) == bytes:
		return ':'.join([item[2:].zfill(2) for item in binToObj(obj, hex)])
	else:
		raise KeyError('Not yet implemented: bytes_to_mac(hex)')

def attempt_int_conversion(bytes):
	try:
		return int(bytes)
	except ValueError:
		try:
			return struct.unpack('>H', bytes)[0]
		except:
			pass

	return None

class PromiscUDPSocket:
	def __init__(self, addr, port, buffer_size=None, worker=None):
		if buffer_size is None:
			buffer_size = args.framesize

		self.addr = addr #ip_to_bytes(addr)
		self.port = port
		self.socket = None
		self.buffer_size = buffer_size
		self.worker = worker

		self.transfers = {

		}

	def __enter__(self):
		self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
		self.socket.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
		
		self.promisciousMode = promisc(self.socket, bytes(args.interface, 'UTF-8'))
		self.promisciousMode.on()

		self.poller = select.epoll()
		self.poller.register(self.socket.fileno(), select.EPOLLIN | select.EPOLLHUP)

		return self

	def __exit__(self, *args):
		self.promisciousMode.off()

		if args[1]:
			traceback.print_tb(args[2])

	def parse_dns_headers(self, data):
		dns_header_fields = [
			'transaction_id',
			'flags',
			'queries',
			'answers_resource_records',
			'authorities_resource_records',
			'additional_resource_records',
		]

		headers_dict = {}

		binary = list(byte_to_bin(data[0:12], bin_map=_DNS_HEADER_STRUCT))
		for index in range(len(binary)):
			headers_dict[dns_header_fields[index]] = {list: binary[index], bytes: bin_str_to_byte(binary[index]), str: None, int: attempt_int_conversion(bin_str_to_byte(binary[index]))}
			headers_dict[dns_header_fields[index]][str] = bytes_to_hex(headers_dict[dns_header_fields[index]][bytes])

		## Parse the frame header
		headers_dict['flags'][dict] = {
			'QR' : int(headers_dict['flags'][list][0][0]),
			'opcode' : int(headers_dict['flags'][list][0][1:5]),
			'authorative_answer' : int(headers_dict['flags'][list][0][5]),
			'truncation' : int(headers_dict['flags'][list][0][6]),
			'recursion_desired' : int(headers_dict['flags'][list][0][7]),
			#?'recursion_available' : int(headers_dict['flags'][list][1][0]),
			#?'zero_field' : int(headers_dict['flags'][list][1][1]),
			#?'response_code' : int(headers_dict['flags'][list][1][4:8])
		}

		#log.info(str(headers_dict))
		#log.info(str({field.name: headers_dict.get(field.name,{}).get(field.type) for field in dataclasses.fields(DNSHeaders)}))

		return DNSHeaders(**{field.name: headers_dict.get(field.name,{}).get(field.type) for field in dataclasses.fields(DNSHeaders)})

	def recv(self):
		if self.socket:
			for fd, event in self.poller.poll(0.001):
				data, auxillary_data_raw, flags, addr = self.socket.recvmsg(self.buffer_size, socket.CMSG_LEN(self.buffer_size))

				if len(data) < 42:
					"""
					Not a valid IPv4 packet so no point in parsing.
					"""
					return None

				segments = struct.unpack("!6s6s2s12s4s4sHHHH", data[0:42])

				ethernet_segments = segments[0:3]
				mac_dest, mac_source = ethernet_segments[:2]
				ip_source, ip_dest = segments[4:6]
				source_port, dest_port, udp_payload_len, udp_checksum = segments[6:10]

				mac_source = bytes_to_mac(mac_source)
				mac_dest = bytes_to_mac(mac_dest)

				ip_source = bytes_to_ip(ip_source)
				ip_dest = bytes_to_ip(ip_dest)

				if dest_port != args.port:
					"""
					Not a valid DNS frame as it's not on our port
					"""
					return None
				
				# log.info(f"{[self.addr]}:{self.port} - Request from {mac_source}->{[ip_source]}:{source_port} to {mac_dest}->{ip_dest}:{dest_port}")

				if (ip_dest == '255.255.255.255' or self.addr == '' or self.addr == ip_dest):
					# log.info(f"DNS Query from {mac_source}->{ip_source}:{source_port} to {mac_dest}->{ip_dest}:{dest_port}")

					if any(data := data[42:42 + udp_payload_len]):
						dns_headers = self.parse_dns_headers(data[:12])
						# dns_data = data[12:]

						return DNSRequest(
							headers=dns_headers,
							raw_data=data[12:],
							addressing=AddressInfo(
								layer2=Layer2(
									source=mac_source,
									destination=mac_dest
								),
								layer3=Layer3(
									source=ip_source,
									destination=ip_dest
								),
								layer4=Layer4(
									source=source_port,
									destination=dest_port
								)
							)
						)

						# log.info(dns_headers)

				break

	def send(self, addressing, payload):
		if self.socket:
			aux_data = [(263, 8, b'\x01\x00\x00\x00<\x00\x00\x00<\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x00\x00')]
			flags = 0

			frame_index = 0
			previous_data = None

			mac_destination = b''.join([struct.pack('B', int(mac_part, 16)) for mac_part in str(addressing.layer2.destination).split(':')])
			mac_source = b''.join([struct.pack('B', int(mac_part, 16)) for mac_part in str(addressing.layer2.source).split(':')])
			mac_frame_type = struct.pack('H', 8)

			mac_header = mac_destination + mac_source + mac_frame_type

			DSC, ECN, reserved_bit = 0, 0, 0
			do_not_fragment, more_fragments, fragment_offset = 1, 0, 0

			version_and_header_length = struct.pack('B', 4 << 4 | 5)
			DSC_ECN = struct.pack('B', DSC << 4 | ECN)
			identification = struct.pack('>H', random.randint(0, 65535))
			fragmentation = struct.pack('>H', reserved_bit << 8 + 7 | do_not_fragment << 8 + 6 | more_fragments << 8 + 5 | fragment_offset)
			ttl = struct.pack('B', 64)
			protocol = struct.pack('B', 17)
			checksum = struct.pack('>H', 0)

			ip_source = b''.join([struct.pack('B', int(addr_part)) for addr_part in str(addressing.layer3.source).split('.')])
			ip_destination = b''.join([struct.pack('B', int(addr_part)) for addr_part in str(addressing.layer3.destination).split('.')])

			udp_source = struct.pack('>H', addressing.layer4.source)
			udp_destination = struct.pack('>H', addressing.layer4.destination)
			udp_checksum = struct.pack('>H', 0)

			# log(f"Telling reciever to set up {repr(stream)}, resending this {resend_buffer} time(s)", fg="gray", level=logging.INFO)
			udp_length = len(payload)

			ethernet = mac_header
			ipv4 = version_and_header_length
			ipv4 += DSC_ECN
			ipv4 += struct.pack('>H', 20 + 8 + udp_length) # 20 = IP Length, 8 = UDP length, len(payload) = data
			ipv4 += identification
			ipv4 += fragmentation
			ipv4 += ttl
			ipv4 += protocol
			ipv4 += checksum
			ipv4 += ip_source
			ipv4 += ip_destination
			udp = udp_source
			udp += udp_destination
			udp += struct.pack('>H', udp_length + 8)
			udp += udp_checksum
			udp += payload

			full_frame = ethernet + ipv4 + udp
			self.socket.sendmsg([full_frame], aux_data, flags, (args.interface, addressing.layer4.destination))
			return True