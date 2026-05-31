import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

ipv4_field_bit_size_mapping = [
	('version', 4), ('header_len', 4), ('tos', 8), ('length', 16), ('id', 16), ('flags', 3),
	('frag_offset', 13), ('ttl', 8), ('proto', 8), ('cksum', 16), ('src', 32), ('dst', 32)
]
icmp_field_bit_size_mapping = [
	('type', 8), ('code', 8), ('cksum', 16)
]
udp_field_bit_size_mapping = [
	('src_port', 16), ('dst_port', 16), ('len', 16), ('cksum', 16)
]


class IPv4:
	# Each member below is a field from the IPv4 packet header.  They are
	# listed below in the order they appear in the packet.  All fields should
	# be stored in host byte order.
	#
	# You should only modify the __init__() method of this class.
	version: int
	header_len: int  # Note length in bytes, not the value in the packet.
	tos: int  # Also called DSCP and ECN bits (i.e. on wikipedia).
	length: int  # Total length of the packet.
	id: int
	flags: int
	frag_offset: int
	ttl: int
	proto: int
	cksum: int
	src: str
	dst: str

	def __init__(self, buffer: bytes):
		assert len(buffer) >= 20, "Buffer too short to be an IPv4 header."
		bit_string = to_bitstring(buffer)
		for field, size in ipv4_field_bit_size_mapping:
			value = bit_string[:size]
			bit_string = bit_string[size:]

			if field in ['src', 'dst']:
				setattr(self, field, to_ip(value))
			elif field == 'header_len':
				setattr(self, field, to_number(value) * 4)
			else:
				setattr(self, field, to_number(value))


	def __str__(self) -> str:
		return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
			f"id {self.id}, flags 0x{self.flags:x}, " + \
			f"ofsset {self.frag_offset}, " + \
			f"proto {self.proto}, header_len {self.header_len}, " + \
			f"len(bytes) {self.length}, cksum 0x{self.cksum:x}) " + \
			f"{self.src} > {self.dst}"


class ICMP:
	# Each member below is a field from the ICMP header.  They are listed below
	# in the order they appear in the packet.  All fields should be stored in
	# host byte order.
	#
	# You should only modify the __init__() function of this class.
	type: int
	code: int
	cksum: int

	def __init__(self, buffer: bytes):
		assert len(buffer) >= 4, "Buffer too short to be an ICMP header."
		bit_string = to_bitstring(buffer)
		for field, size in icmp_field_bit_size_mapping:
			value = to_number(bit_string[:size])
			bit_string = bit_string[size:]
			setattr(self, field, value)

	def __str__(self) -> str:
		return f"ICMP (type {self.type}, code {self.code}, " + \
			f"cksum 0x{self.cksum:x})"


class UDP:
	# Each member below is a field from the UDP header.  They are listed below
	# in the order they appear in the packet.  All fields should be stored in
	# host byte order.
	#
	# You should only modify the __init__() function of this class.
	src_port: int
	dst_port: int
	len: int
	cksum: int

	def __init__(self, buffer: bytes):
		bit_string = to_bitstring(buffer)
		for field, size in udp_field_bit_size_mapping:
			value = bit_string[:size]
			bit_string = bit_string[size:]
			setattr(self, field, to_number(value))

	def __str__(self) -> str:
		return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
			f"len {self.len}, cksum 0x{self.cksum:x})"


def to_bitstring(buffer: bytes) -> str:
	return ''.join(format(byte, '08b') for byte in [*buffer])


def to_number(bit_string: str) -> int:
	return int(bit_string, 2)


def to_ip(bit_string: str) -> str:
	octets = [str(to_number(bit_string[i:i + 8])) for i in range(0, 32, 8)]
	return '.'.join(octets)


TIME_EXCEED_TYPE = 11
DEST_UNREACH_TYPE = 3
DEST_UNREACH_PORT_CODE = 3
TTL_EXPIRED_CODE = 0

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
		-> list[list[str]]:
	""" Run traceroute and returns the discovered path.

	Calls util.print_result() on the result of each TTL's probes to show
	progress.

	Arguments:
	sendsock -- This is a UDP socket you will use to send traceroute probes.
	recvsock -- This is the socket on which you will receive ICMP responses.
	ip -- This is the IP address of the end host you will be tracerouting.

	Returns:
	A list of lists representing the routers discovered for each ttl that was
	probed.  The ith list contains all of the routers found with TTL probe of
	i+1.   The routers discovered in the ith list can be in any order.  If no
	routers were found, the ith list can be empty.  If `ip` is discovered, it
	should be included as the final element in the list.
	"""
	result: list[list[str]] = []
	get_reply_from_ip = False
	for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
		if get_reply_from_ip:
			break
		discovered_routers = set()
		for attempt in range(PROBE_ATTEMPT_COUNT):
			sendsock.set_ttl(ttl)
			sendsock.sendto("hello".encode(), (ip, TRACEROUTE_PORT_NUMBER))
			if recvsock.recv_select():
				buff, address = recvsock.recvfrom()
				ipv4_packet = IPv4(buff)
				if ipv4_packet.proto != util.IPPROTO_ICMP:
					continue

				icmp_offset = ipv4_packet.header_len
				icmp_package = ICMP(buff[icmp_offset:])
				if ipv4_packet.src == ip and icmp_package.type == DEST_UNREACH_TYPE and icmp_package.code == DEST_UNREACH_PORT_CODE:
					discovered_routers.add(ipv4_packet.src)
					get_reply_from_ip = True
					break
				if icmp_package.type == TIME_EXCEED_TYPE and icmp_package.code == TTL_EXPIRED_CODE:
					discovered_routers.add(ipv4_packet.src)

		discovered_routers_list = list(discovered_routers)
		util.print_result(discovered_routers_list, ttl)
		result.append(discovered_routers_list)

	return result


if __name__ == '__main__':
	args = util.parse_args()
	ip_addr = util.gethostbyname(args.host)
	print(f"traceroute to {args.host} ({ip_addr})")
	traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
