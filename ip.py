import array
import os
import struct
import socket
import time
import typing
from collections import namedtuple
from types import SimpleNamespace


""" TODO
    1. (OK)add `make_ping` method to class ICMPv4.
"""

""" PROP
    1. more verbose `ping_*` function.
    2. `Monitor` class for non-blocking, multiple host status polling.
    3. substitute mutiple return value with custom namedtuple
    4. Mapping ICMPv4 parse result to Enum.
"""

_IPhdr_test = ">B"
# first byte of a packet, should contain version info.

_IPv4_hdr_lo = ">BBHHHBBHLL"
_ICMP_hdr_lo = "BBHHH"

_IPv4_struct = struct.Struct(_IPv4_hdr_lo)
_ICMPv4_struct = struct.Struct(_ICMP_hdr_lo)

DEFAULT_TIMEOUT =   2000            # ms
DEFAULT_INTERVAL =  1000            # ms
DEFAULT_PING_PAYLOAD = b"A\x00"
DEFAULT_RCV_BUFSZ = 1024

IPv4_MAX_SZ = (1 << 16) - 1


Addrinfo = namedtuple(
    "Addrinfo",
    ["family", "type", "proto", "canonname", "sockaddr"]
)


PingState = typing.Tuple[bool, float]


class ICMPType(SimpleNamespace):
    EchoRequest = 8
# _ICMP_table = {i.value: i for i in ICMPType}

def _inet_checksum(data: bytes) -> int:
    # TODO: ensure the length of data must be multiple of words.
    u16_arr = array.array("H", data)
    chksum = 0
    for i in u16_arr:
        chksum += (i & 0xFFFF)
    chksum =    (chksum >> 16) + (chksum & 0xFFFF)
    chksum +=   (chksum >> 16)
    return (~chksum) & 0xFFFF

def _u32_to_dot(u32: int) -> tuple:
    b = struct.pack(">L", u32)
    return struct.unpack(">BBBB", b)

def _get_ip_ver(b: bytes) -> int:
    u8 = struct.unpack(_IPhdr_test, b[:1])
    ver = (u8[0] & 0xF0) >> 4
    return ver


# parsing data returned by "recvfrom" function.

class IPv4():
    """Simple IPv4 packet parser."""
    def __init__(self, b: bytes):
        ver = _get_ip_ver(b)
        if not (ver == 4 or ver == 6):
            raise ValueError("{} is not a valid IP version".format(ver))
        v4 = _IPv4_struct.unpack(b[:20]) # fixed length of 20 bytes

        self.ver = ver
        self.ihl =      v4[0] & 0xF         # header length in dwords
        self.ds =       v4[1] & 0xFC >> 2
        self.ecn =      v4[1] & 0x3
        self.size =     v4[2]               # total packet size
        self.ident =    v4[3]
        self.flags =    v4[4] & 0xE0 >> 5
        self.offset =   v4[4] & 0x1F
        self.ttl =      v4[5]
        self.proto =    v4[6]
        self.checksum = v4[7]
        self.raw_src =  v4[8]
        self.raw_dst =  v4[9]
        self.src = _u32_to_dot(self.raw_src)
        self.dst = _u32_to_dot(self.raw_dst)

        assert _inet_checksum(b[:20]) == 0

        # handling header option and payload
        rem = b[20:]
        self.raw_options = rem[:self.ihl*4 - 20]
        rem = rem[self.ihl*4 - 20:]
        self.payload = rem[:]
        # TODO: add a `rem` field for undigested bytes.
        return


class ICMPv4():
    """Simple ICMPv4 parser only for ping packets."""
    def __init__(self, b: bytes):
        # TODO: complete check
        icmpv4 = _ICMPv4_struct.unpack(b[:8])

        self.type =     icmpv4[0]
        self.code =     icmpv4[1]
        self.checksum = icmpv4[2]
        self.id =       icmpv4[3]
        self.seq =      icmpv4[4]
        
        self.payload = b[2*4:]
        return

    @staticmethod
    def make_ping() -> bytes:
        #payload: bytes=b'A\x00'
        #sz = len(payload)
        ## if payload size violates:
        #if (sz > (IPv4_MAX_SZ - 8)):
        #    #   1) maximum ipv4 packet size
        #    raise Exception("Payload size too big: {}".format(sz))
        #if (sz & 0b1):
        #    #   2) is not multiple of 4 (sizeof(uint32_t))
        #    raise Exception("Payload size is not multiple of 2 bytes")
        data = DEFAULT_PING_PAYLOAD
        pid = os.getpid()
        s = b""
        # NOTE: we can modify `id` and `sequence` field for identification.
        # for example, current time as payload
        header = _ICMPv4_struct.pack(
            ICMPType.EchoRequest, 0,
            0,          pid, 0
        )
        chksum = _inet_checksum(header + data)
        header = _ICMPv4_struct.pack(
            ICMPType.EchoRequest, 0,
            chksum,     pid, 0
        )
        s = header + data
        assert _inet_checksum(s) == 0
        return s


""" ping methods
    - once      OK
    - multi     TODO
    - ...
"""
class Ping():
    def __init__(self):
        proto_icmp = socket.getprotobyname("icmp")
        self.sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            proto_icmp
        )
        self.packet = ICMPv4.make_ping()
        return
    
    def _ping(
            self, addr: typing.Tuple[typing.Tuple, int],
            timeout: int=DEFAULT_TIMEOUT
        ) -> typing.Tuple[bool, float]:
        ok = True
        dt = time.perf_counter()
        try:
            self.sock.sendto(self.packet, addr)
            # TODO: make use of `raw` and `addr`
            _, _ = self.sock.recvfrom(DEFAULT_RCV_BUFSZ)
        except socket.timeout:
            ok = False
        dt = time.perf_counter() - dt
        if not ok:
            dt = 0
        return ok, dt

    @staticmethod
    def _get_icmp_addrif(host: str) -> Addrinfo:
        """
        Return the first available IPv4 addrinfo.
        """
        addrif = None
        try:
            _if = socket.getaddrinfo(
                host, 1, socket.AF_INET,
                socket.SOCK_DGRAM,
                socket.IPPROTO_ICMP
            )
        except socket.gaierror:
            raise Exception("Host unresolvable: {}".format(host))
        for af, *rem in _if:
            if af == socket.AF_INET:
                addrif = Addrinfo(af, *rem)
        if addrif is None:
            raise Exception(
                "No available IPv4 address for host{}.".format(host)
            )
        return addrif

    def ping_once(
            self, host: str,
            timeout: int=DEFAULT_TIMEOUT
        ) -> PingState:
        addrif = self._get_icmp_addrif(host)
        self.sock.settimeout(timeout/1000)
        suc, dt = self._ping(addrif.sockaddr, timeout)
        return suc, dt

    def ping_multi(
            self, host: str, count: int, interval: int, timeout: int
        ) -> typing.List[PingState]:
        addrif = self._get_icmp_addrif(host)
        res = list()
        interval /= 1000
        self.sock.settimeout(timeout/1000)
        for _ in range(count):
            # a little function call overhead should not ba a problem?
            res.append(self._ping(addrif.sockaddr, timeout))
            time.sleep(interval)
        return res

    # def ping_verbose ...
    # 

    class Monitor():
        pass
        # send all ping requests at once
        # vs
        # non-blocking polling

