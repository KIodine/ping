import array
import logging
import os
import socket
import struct
import time
import typing
from collections import namedtuple
from types import SimpleNamespace

from .logger import get_logger as pget_logger

__all__ = [
    "IPv4",
    "IPv6",
    "ICMPv4",
    "ICMPv6"
]

"""
IP packets and ICMP packets analysis. Also provides simple protocol-independent
routines.
"""

# must convert endianess to net-endian if byte size greater than 1 before
# store them into memory.

plog: logging.Logger = pget_logger().getChild("ip")


class Defaults(SimpleNamespace):
    MaxPayloadSize      = (1024-20-8)
    EchoRequestPayload  = b"A\x00"


class HeaderStruct(SimpleNamespace):
    # struct defination -----------------------------
    _IPv4_hdr_lo        = "!BBHHHBBHLL"
    _IPv6_hdr_lo        = "!LHBB16p16p"
    _ICMPv4_hdr_lo      = "!BBH"
    _ICMPv6_hdr_lo      = "!BBH"
    _psuedo_v6_hdr_lo   = "!16p16pLL"
    _general_icmp_lo    = "!BBH4p"
    # ICMPv4
    _v4_echo_reply       = "!HH"
    # ICMPv6
    _v6_echo_reply       = "!HH"
    # struct instance -------------------------------
    IPv4        = struct.Struct(_IPv4_hdr_lo)
    IPv6        = struct.Struct(_IPv6_hdr_lo)
    ICMPv4      = struct.Struct(_ICMPv4_hdr_lo)
    ICMPv6      = struct.Struct(_ICMPv6_hdr_lo)
    Psuedov6    = struct.Struct(_psuedo_v6_hdr_lo)
    GeneralICMP = struct.Struct(_general_icmp_lo)
    v4EchoReply = struct.Struct(_v4_echo_reply)
    v6EchoReply = struct.Struct(_v6_echo_reply)


# python w32 doesn't define.
_IPPROTO_ICMPv6 = 58

class ICMPv4Type(SimpleNamespace):
    EchoReply               = 0
    DestinationUnreachable  = 3
    SourceQuench            = 4
    RedirectMessage         = 5
    EchoRequest             = 8
    TimeExceeded            = 11


class ICMPv6Type(SimpleNamespace):
    # error messages -------------
    DestinationUnreachable  = 1
    PacketTooBig            = 2
    TimeExceeded            = 3
    ParameterProblem        = 4
    # information messages -------
    EchoRequest             = 128
    EchoReply               = 129


def inet_checksum(data: bytes) -> int:
    u16_arr = array.array("H", data)
    chksum = 0
    for i in u16_arr:
        # x86 machine reads memory as LE, convert these numbers to BE first.
        i = socket.htons(i)
        chksum += (i & 0xFFFF)
    chksum =    (chksum >> 16) + (chksum & 0xFFFF)
    chksum +=   (chksum >> 16)
    return (~chksum) & 0xFFFF

def u32_to_dot(u32: int) -> tuple:
    b = struct.pack("!L", u32)
    return struct.unpack("!BBBB", b)

def get_ip_ver(b: bytes) -> int:
    ver = (b[0] & 0xF0) >> 4
    return ver

def make_icmp_packet(
        msg_type: int, msg_code: int, u32: bytes, payload: bytes
    ) -> bytes:
    """Protocol-independent ICMP packet maker."""
    pad_byte = b"\x00"
    hdr = HeaderStruct.GeneralICMP.pack(msg_type, msg_code, 0, u32)
    if (
        (msg_type == ICMPv4Type.EchoRequest) or \
        (msg_type == ICMPv6Type.EchoRequest)
       ) and \
       ((len(payload) & 0b1) == 1):
        chksum = inet_checksum(hdr + payload + pad_byte)
    else:
        chksum = inet_checksum(hdr + payload)
    hdr = HeaderStruct.GeneralICMP.pack(msg_type, msg_code, chksum, u32)
    return hdr + payload

def make_icmp_ping(
        ident: int, seq_num: int, payload: bytes
    ) -> bytes:
    """Short routine for making ICMPv4 echo request message."""
    if (len(payload) > Defaults.MaxPayloadSize):
        raise ValueError(
            ("payload larger than default size limit: {}, large payload may"
             "results in IP packet fragment.").format(Defaults.MaxPayloadSize)
        )
    u32_buf = struct.pack("!HH", ident & 0xFFFF, seq_num & 0xFFFF)
    return make_icmp_packet(
            ICMPv4Type.EchoRequest,
            0, u32_buf, payload
        )

def make_simple_ping() -> bytes:
    """Make ping message with default payload."""
    return make_icmp_ping(
            0 , 0, Defaults.EchoRequestPayload
        )


class IPv4():
    """Simple IPv4 packet parser."""
    def __init__(self, b: bytes):
        ver = get_ip_ver(b)
        if ver != 4:
            raise ValueError("{} is not a valid IP version".format(ver))
        v4 = HeaderStruct.IPv4.unpack(b[:20])

        self.ver        = ver
        self.ihl        = v4[0] & 0xF         # header length in dwords
        self.ds         = v4[1] & 0xFC >> 2
        self.ecn        = v4[1] & 0x3
        self.size       = v4[2]               # total packet size
        self.ident      = v4[3]
        self.flags      = v4[4] & 0xE000 >> 13
        self.offset     = v4[4] & 0x1FFF
        self.ttl        = v4[5]
        self.proto      = v4[6]
        self.checksum   = v4[7]
        self.raw_src    = v4[8]
        self.raw_dst    = v4[9]
        self.src        = u32_to_dot(self.raw_src)
        self.dst        = u32_to_dot(self.raw_dst)

        # handling header option and payload
        opt_limit = self.ihl*4 - 20
        payload_limit = self.size - self.ihl*4
        rem = b[20:]
        self.raw_options = rem[:opt_limit]
        rem = rem[opt_limit:]   # moving the "pointer"
        self.payload = rem[:payload_limit]
        rem = rem[payload_limit:]

        self.rem = rem[:]       # field for undigetsed bytes.
        return
    pass


class IPv6():
    """Simple IPv6 packet parser."""
    def __init__(self, b: bytes):
        ver = get_ip_ver(b)
        if ver != 6:
            raise ValueError("Invalid version number: {}".format(ver))
        v6 = HeaderStruct.IPv6.unpack(b[:40])
        self.ver = ver
        self.traffic_class  = (v6[0] >> 20) & 0xFF
        self.flow_lable     = v6[0] & 0xFFFFF
        self.payload_length = v6[1]
        self.next_header    = v6[2]
        self.hop_limit      = v6[3]
        self.src_addr       = v6[4]
        self.dst_addr       = v6[5]
        self.payload        = b[40:]
        return

    def make_psuedo_hdr(self, pack_length: int) -> bytes:
        raw_hdr = HeaderStruct.Psuedov6.pack(
            self.src_addr, self.dst_addr,
            pack_length, self.next_header & 0xFF
        )
        return raw_hdr


class ICMPv4():
    def __init__(self, b: bytes):
        icmpv4 = HeaderStruct.ICMPv4.unpack(b[:4])
        self.type = icmpv4[0]
        self.code = icmpv4[1]
        self.checksum = icmpv4[2]
        self.msg_body = b[4:]
        return

    def as_echo_reply4(self) -> typing.Tuple[int, int, bytes]:
        ident, seq_num = HeaderStruct.v4EchoReply.unpack(self.msg_body[:4])
        return (ident, seq_num, self.msg_body[4:])


class ICMPv6():
    def __init__(self, b: bytes):
        icmpv6 = HeaderStruct.ICMPv4.unpack(b[:4])
        self.type = icmpv6[0]
        self.code = icmpv6[1]
        self.checksum = icmpv6[2]
        self.msg_body = b[4:]

    def as_echo_reply6(self) -> typing.Tuple[int, int, bytes]:
        ident, seq_num = HeaderStruct.v4EchoReply.unpack(self.msg_body[:4])
        return (ident, seq_num, self.msg_body[4:])


def is_icmp_echo_reply(raw: bytes):
    ver = get_ip_ver(raw)
    is_er = False
    if   ver == 4:
        v4 = IPv4(raw)
        if v4.proto == socket.IPPROTO_ICMP:
            icmp = ICMPv4(v4.payload)
            is_er = (icmp.type == ICMPv4Type.EchoReply)
    elif ver == 6:
        v6 = IPv6(raw)
        if v6.next_header == _IPPROTO_ICMPv6:
            icmp = ICMPv6(v6.payload)
            is_er = (icmp.type == ICMPv6Type.EchoReply)
    return is_er

def parse_packet4(b: bytes):
    ip_pack = IPv4(b)
    if ip_pack.proto != socket.IPPROTO_ICMP:
        return
    chksum = inet_checksum(ip_pack.payload)
    if chksum != 0:
        plog.error("Checksum error")
    icmp_pack = ICMPv4(ip_pack.payload)
    return (ip_pack, icmp_pack)

def parse_packet6(b: bytes):
    ip_pack = IPv6(b)
    if ip_pack.next_header != socket.IPPROTO_ICMP:
        return
    chksum = inet_checksum(
        ip_pack.make_psuedo_hdr(ip_pack.payload_length) + \
        ip_pack.payload
    )
    if chksum != 0:
        plog.error("Checksum error")
    icmp_pack = ICMPv6(ip_pack.payload)
    return (ip_pack, icmp_pack)

def parse_packet(b: bytes) -> tuple:
    # TODO: do checksum out side IP classes.
    ver = get_ip_ver(b)
    if   ver == 4:
        return parse_packet4(b)
    elif ver == 6:
        return parse_packet6(b)
    else:
        pass
    return
