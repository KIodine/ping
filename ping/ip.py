import array
import operator
import os
import select
import socket
import struct
import time
import typing
from collections import namedtuple
from contextlib import contextmanager
from types import SimpleNamespace


__all__ = [
    "IPv4",
    "ICMPv4",
    "Ping",
]

""" <NOTE>
    This library focus on only correct `echo_reply` messege,
    other messeges are considered as error.
"""


""" <TODO>
    - IPv6 compatibility.


    <PROPOSAL>
    - refining functions.
    - a "no exception" version of ping.
    - `Monitor` class for non-blocking, multiple host status polling.
    - substitute mutiple return value with custom namedtuple
    - Mapping ICMPv4 parse result to Enum.
    - multi-process/multi-thread version
    - super massive ping(kind of illegal)
    - customiszble ping payload
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
Sockaddr = typing.Tuple[typing.Tuple, int]
# IPv4_Callback = typing.Callable[[IPv4,], typing.Any]
# ICMPv4_Callback = typing.Callble[[ICMPv4,], typing.Any]


class ICMPType(SimpleNamespace):
    EchoReply               = 0
    DestinationUnreachable  = 3
    SourceQuench            = 4
    RedirectMessage         = 5
    EchoRequest             = 8
    TimeExceeded            = 11
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

def _is_valid_v4addr(s: str) -> bool:
    """Test a string is one of domain name or dot-decimal representation."""
    v4s = s.split(".")
    length = len(v4s)
    if length > 1 and v4s[0].isalpha():
        # assume it is hostname
        return True
    # check is dot-decimal format
    if length != 4:
        return False
    for d in v4s:
        if not d.isalnum() or not (255 >= int(d) >= 0):
            return False
    return True

def make_simple_ping() -> bytes:
    # make an ICMPv4 echo request packet.
    data = DEFAULT_PING_PAYLOAD
    pid = os.getpid()
    s = b""
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

def get_icmp_addrif(host: str, version: int) -> Addrinfo:
    addrif: Addrinfo = None
    if not version in (socket.AF_INET, socket.AF_INET6):
        raise Exception("{} is not a valid IP version".format(version))
    try:
        ai = socket.getaddrinfo(
            host, 0,
            version,
            socket.SOCK_RAW,
            socket.getprotobyname("ICMP"),
            socket.AI_CANONNAME
        )
    except socket.gaierror:
        pass
    for af, *rem in ai:
        if af == version:
            addrif = Addrinfo(af, *rem)
    return addrif

@contextmanager
def _set_timeout(socket: socket.socket, timeout: float):
    old_timeout = socket.gettimeout()
    socket.settimeout(timeout)
    try:
        yield
    finally:
        # restore timeout anyway.
        socket.settimeout(old_timeout)
    return


class IPv4():
    """Simple IPv4 packet parser."""
    def __init__(self, b: bytes):
        ver = _get_ip_ver(b)
        if not (ver == 4 or ver == 6):
            raise ValueError("{} is not a valid IP version".format(ver))
        v4 = _IPv4_struct.unpack(b[:20]) # fixed length of 20 bytes

        self.ver        = ver
        self.ihl        = v4[0] & 0xF         # header length in dwords
        self.ds         = v4[1] & 0xFC >> 2
        self.ecn        = v4[1] & 0x3
        self.size       = v4[2]               # total packet size
        self.ident      = v4[3]
        self.flags      = v4[4] & 0xE0 >> 5
        self.offset     = v4[4] & 0x1F
        self.ttl        = v4[5]
        self.proto      = v4[6]
        self.checksum   = v4[7]
        self.raw_src    = v4[8]
        self.raw_dst    = v4[9]
        self.src        = _u32_to_dot(self.raw_src)
        self.dst        = _u32_to_dot(self.raw_dst)

        assert _inet_checksum(b[:self.ihl*4]) == 0

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
    
    # TODO: implement `__repr__` method


class ICMPv4():
    """Simple ICMPv4 parser only for ping packets."""
    def __init__(self, b: bytes):
        # TODO: complete check
        icmpv4 = _ICMPv4_struct.unpack(b[:8])

        self.type       = icmpv4[0]
        self.code       = icmpv4[1]
        self.checksum   = icmpv4[2]
        # the following fields are actually type-dependent.
        self.id         = icmpv4[3]
        self.seq        = icmpv4[4]
        self.payload    = b[2*4:]
        return

    # TODO: implement `__repr__` method


class _PacketRecord():
    """Auxillary class for package loading and delay calculation."""
    def __init__(self):
        self.send_time      = time.time()
        self.recv_time      = float("inf")
        self.ip_pack        = None
        self.icmp_pack      = None
        self.is_echo_reply  = False
        return
    
    def parse_packet(self, b: bytes):
        self.recv_time = time.time()
        self.ip_pack = IPv4(b)
        if self.ip_pack.proto == socket.IPPROTO_ICMP:
            self.icmp_pack = ICMPv4(self.ip_pack.payload)
            if self.icmp_pack.type == ICMPType.EchoReply:
                self.is_echo_reply = True
        return
    
    def get_delay(self) -> float:
        if self.ip_pack is not None and self.is_echo_reply is True:
            return self.recv_time - self.send_time
        return float("NaN")

    def as_namedtuple(self):
        return


class _PingMultiRecord():
    """Auxiliary data carrier."""
    def __init__(self, host: str, addrif: Addrinfo):
        self.host       = host
        self.addrinfo   = addrif
        self.packet_record: _PacketRecord   = None
        self.res: typing.Any                = None
        return


class Ping():
    def __init__(self):
        proto_icmp = socket.getprotobyname("icmp")
        self.sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            proto_icmp
        )
        self.packet = make_simple_ping()
        return
    
    def __del__(self):
        self.sock.close()
        return

    def _send_icmp_er(
            self, sockaddr: Sockaddr,
            ipv4_callback: typing.Callable,
            icmpv4_callback: typing.Callable
        ) -> typing.Tuple[float, typing.Any, typing.Any]:
        """ Low level ping function.
            Accept two callbacks for both IPv4 and ICMPv4 packets, returning
            time cost and results of corresponding callback.
            Note that `icmpv4_callback` will be called only if IPv4 packet
            contains correct ICMPv4 packet.
        """
        # NOTE: seems callbacks are some kind of redundant.
        t0 = time.perf_counter()
        dt = 0.0
        ipv4_cb_res: typing.Any     = None
        icmpv4_cb_res: typing.Any   = None
        ip_pack: IPv4               = None
        icmp_pack: ICMPv4           = None
        try:
            _ = self.sock.sendto(self.packet, sockaddr)
            raw, _ = self.sock.recvfrom(DEFAULT_RCV_BUFSZ)
            dt = time.perf_counter() - t0
            ip_pack = IPv4(raw)
            ipv4_cb_res = ipv4_callback(ip_pack) if ipv4_callback is not None\
                else ip_pack
            if ip_pack.proto == socket.IPPROTO_ICMP:
                icmp_pack = ICMPv4(ip_pack.payload)
                icmpv4_cb_res = icmpv4_callback(icmp_pack) \
                    if icmpv4_callback is not None\
                    else icmp_pack
        except socket.timeout:
            dt = float("NaN")
        return (dt, ipv4_cb_res, icmpv4_cb_res)

    def ping_once(
            self, host: str,
            timeout: int=DEFAULT_TIMEOUT
        ) -> typing.Tuple[float, bool]:
        """Simply ping the host."""
        dt  = 0
        suc = False
        if not _is_valid_v4addr(host):
            raise Exception("{} is probably not a valid address.".format(host))
        addrif = get_icmp_addrif(host, socket.AF_INET)
        if addrif is None:
            raise Exception("No addrinfo for host: {}".format(host))
        with _set_timeout(self.sock, timeout/1000):
            dt, _, icmpv4 = self._send_icmp_er(
                addrif.sockaddr, None, None
            )
            if icmpv4 is not None and icmpv4.type == ICMPType.EchoReply:
                suc = True
        return (dt, suc)

    def ping_seq(
            self, host: str, count: int,
            interval: int,
            timeout: int=DEFAULT_TIMEOUT
        ) -> typing.List[typing.Tuple[float, bool]]:
        """Ping host for `count` times with `interval` delay."""
        dt  = 0
        suc = False
        if not _is_valid_v4addr(host):
            raise Exception("{} is probably not a valid address.".format(host))
        addrif = get_icmp_addrif(host, socket.AF_INET)
        if addrif is None:
            raise Exception("No addrinfo for host: {}".format(host))
        res = list()
        interval /= 1000
        with _set_timeout(self.sock, timeout/1000):
            for _ in range(count):
                dt, _, icmpv4 = self._send_icmp_er(addrif.sockaddr, None, None)
                if icmpv4 is not None and icmpv4.type == ICMPType.EchoReply:
                    suc = True
                res.append((dt, suc))
                time.sleep(interval)
        return res

    def _con_send_icmp_er(
            self, pmr_list: typing.List[_PingMultiRecord],
            timeout: int
        ) -> dict:
        """Concurrent icmp echo request sender."""
        packet_sent = 0
        # in C we'll use BST or hash table.
        addr_pmr_map = {
            pmr.addrinfo.sockaddr[0]: pmr
            for pmr in pmr_list
        }
        socket_list = [self.sock,]
        # NOTE: maybe some day a multi socket multiping?
        # NOTE: Some issues from `multi-ping` library reported that
        #   burst ping results in packet loss, it can (probably) be eliminated
        #   by introducing a small amount of delay between each 
        #   packet dispatching.
        for pmr in pmr_list:
            addr, _ = pmr.addrinfo.sockaddr
            _ = self.sock.sendto(self.packet, pmr.addrinfo.sockaddr)
            addr_pmr_map[addr].packet_record = _PacketRecord()
            packet_sent += 1
            #time.sleep(SEND_DELAY)
        rem_timeout = timeout/1000
        rem_recv = packet_sent
        while True:
            t0 = time.perf_counter()
            r, _, _ = select.select(socket_list, [], [], rem_timeout)
            if r != []:
                for sock in r:
                    raw, (addr, _) = sock.recvfrom(DEFAULT_RCV_BUFSZ)
                    addr_pmr_map[addr].packet_record.parse_packet(raw)
                    rem_recv -= 1
                    dt = time.perf_counter() - t0
                    rem_timeout -= dt
                if rem_recv == 0:
                    # if we retrived all packet, break out early.
                    break
            else:
                # `select` timeouts.
                break
        return addr_pmr_map

    def _ping_multi(
            self, host_list: typing.List[str],
            timeout: int=DEFAULT_TIMEOUT,
            pr_callback: typing.Callable[[_PacketRecord,], typing.Any]=None
        ) -> typing.Dict[str, _PingMultiRecord]:
        """
        Bottom layer of `ping_multi`, accepting a callback for preprocess.
        If callback is None, the raw `_PacketRecord` instances are exposed.
        """
        # host -> addr -> PacketRecord
        # PROPOSAL: An optional parameter of a dict for storing result,
        #   saving memory and construction time.
        for host in host_list:
            if not _is_valid_v4addr(host):
                raise Exception(
                    "{} is probably not a valid address.".format(host)
                )
        pmr_list = [
            _PingMultiRecord(
                host, get_icmp_addrif(host, socket.AF_INET)
            )
            for host in host_list
        ]
        for pmr in pmr_list:
            if pmr.addrinfo is None:
                raise Exception("No addrinfo for host: {}".format(pmr.host))
        
        _ = self._con_send_icmp_er( # addr_pmr_map
            pmr_list, timeout
        )
        # TODO: generalize the following part, exposing `_PacketRecord`
        #   elements.(DONE)
        #   -> a callback of `void* (*cb)(_PacketRecord* pr)`
        # host: addr; addr: _PacketRecord
        # if we receive (addr, _PacketRecord), how to map host to 
        # `_PacketRecord`?
        # addr: (host, ai, _PacketRecord)
        for pmr in pmr_list:
            if pr_callback is not None:
                pmr.res = pr_callback(pmr.packet_record)
            pass
        return pmr_list

    def ping_multi(
            self, host_list: typing.List[str],
            timeout: int=DEFAULT_TIMEOUT,
            mapping: dict=None
        ) -> typing.Dict[str, float]:
        """
            Ping multiple hosts at a time, return a dict of host to delay and
            `True` if succeeded.
            An optional `mapping` parameter can be passed as an alternative 
            destination of results.
        """
        host_delay_map: typing.Dict[str, float] = None
        get_delay_cb = operator.methodcaller("get_delay")
        res = self._ping_multi(
                host_list, timeout=timeout,
                pr_callback=get_delay_cb
            )
        if mapping is None:
            host_delay_map = {
                pmr.host: pmr.res
                for pmr in res
            }
        else:
            host_delay_map = mapping
            for pmr in res:
                host_delay_map[pmr.host] = pmr.res
        
        return host_delay_map
