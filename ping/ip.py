import array
import logging
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

from .logger import get_logger as pget_logger

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
        - IPv6 requires another v6 socket, how do we dispatch two different
          kinds of packets?
          -> establish some switch mechanism for:
            - `_PacketRecord`
            - `_PingMultiRecord`
            - `_send_icmp_er`
            - `_con_send_icmp_er`
            - `_ping_multi`
    - use `logging` than naive `print`.
    - an option of `ping_multi`(and others) for silently handling unresolvable
      hosts.
    - investigate why sometimes `_ping_multi` got huge delay.
    - seperate class `Ping` to `ping.py`
    - add `as_<ICMP msg type>` method for flexible data intepretation.
    - support ICMP `TimeExceed` message, or further, all icmp messages.


    <PROPOSAL>
    - refining functions.
    - asyncio version ping
    - a "no exception" version of ping.
    - substitute mutiple return value with custom namedtuple
    - Mapping ICMPv4 parse result to Enum.
    - multi-process/multi-thread version
    - support super massive ping(kind of illegal)
    - caching addrinfo results(DONE)
    - multi-socket ping
"""

plog: logging.Logger = pget_logger().getChild("ip")


class HeaderStruct(SimpleNamespace):
    # struct defination -----------------------------
    _IPv4_hdr_lo        = "!BBHHHBBHLL"
    _IPv6_hdr_lo        = "!LHBB16p16p"
    _ICMPv4_hdr_lo      = "!BBHHH"
    _ICMPv6_hdr_lo      = "!BBHHH"      # just for compatitive, will be fixed.
    _psuedo_v6_hdr_lo   = "!16p16pLL"
    # struct instance -------------------------------
    IPv4        = struct.Struct(_IPv4_hdr_lo)
    IPv6        = struct.Struct(_IPv6_hdr_lo)
    ICMPv4      = struct.Struct(_ICMPv4_hdr_lo)
    ICMPv6      = struct.Struct(_ICMPv6_hdr_lo)
    Psuedov6    = struct.Struct(_psuedo_v6_hdr_lo)


_IPPRPTO_ICMPv6 = 58    # python win32 doesn't have this defined.

DEFAULT_TIMEOUT =   2000.0/1000.0
DEFAULT_INTERVAL =  1000.0/1000.0
DEFAULT_PING_PAYLOAD = b"A\x00"
DEFAULT_RCV_BUFSZ = 1024
DEFAULT_PAYLOAD_SZ = 1024   # - 20 - 2*2 - 4

IPv4_MAX_SZ = (1 << 16) - 1


Addrinfo = namedtuple(
    "Addrinfo",
    ["family", "type", "proto", "canonname", "sockaddr"]
)

Sockaddr = typing.Tuple[str, int]

Sockaddr4 = namedtuple(
    "Sockaddr4",
    ["address", "port"]
)

Sockaddr6 = namedtuple(
    "Sockaddr6",
    ["address", "port", "flow_info", "scope_id"]
)

EchoReply4 = namedtuple(
    "EchoReply4",
    ["ident", "seq_num", "payload"]
)

EchoReply6 = namedtuple(
    "EchoReply6",
    ["ident", "seq_num", "payload"]
)

PingState = typing.Tuple[bool, float]
Sockaddr = typing.Tuple[typing.Tuple, int]
# IPv4_Callback = typing.Callable[[IPv4,], typing.Any]
# ICMPv4_Callback = typing.Callble[[ICMPv4,], typing.Any]


class ICMPv4Type(SimpleNamespace):
    EchoReply               = 0
    DestinationUnreachable  = 3
    SourceQuench            = 4
    RedirectMessage         = 5
    EchoRequest             = 8
    TimeExceeded            = 11
# _ICMP_table = {i.value: i for i in ICMPv4Type}

class ICMPv6Type(SimpleNamespace):
    # error messages -------------
    DestinationUnreachable  = 1
    PacketTooBig            = 2
    TimeExceeded            = 3
    ParameterProblem        = 4
    # information messages -------
    EchoRequest             = 128
    EchoReply               = 129


def _inet_checksum(data: bytes) -> int:
    # TODO: ensure the length of data must be multiple of words.
    #   -> `array` do the check itself.
    u16_arr = array.array("H", data)
    chksum = 0
    for i in u16_arr:
        # x86 machine reads memory as LE, convert these numbers to BE first.
        i = socket.htons(i)
        chksum += (i & 0xFFFF)
    chksum =    (chksum >> 16) + (chksum & 0xFFFF)
    chksum +=   (chksum >> 16)
    return (~chksum) & 0xFFFF

def _u32_to_dot(u32: int) -> tuple:
    b = struct.pack(">L", u32)
    return struct.unpack(">BBBB", b)

def _get_ip_ver(b: bytes) -> int:
    ver = (b[0] & 0xF0) >> 4
    return ver

def _make_icmp_packet(
        msg_type: int, msg_code: int, u32: int, payload: bytes
    ) -> bytes:
    pad = b"\x00"
    hdr = struct.pack("!BBH4p", msg_type, msg_code, 0, u32)
    if msg_type == ICMPv4Type.EchoRequest and (len(payload) & 0b1) == 1:
        # RFC 792 echo request -> checksum
        chksum = _inet_checksum(hdr + payload + pad)
    else:
        chksum = _inet_checksum(hdr + payload)
    # NOTE: Remember to flip checksum as well
    # this turns chksum to net-endian, but turn back after packed, why?
    # -> because we checksum the sequence as LE shorts, but it is actually
    #    BE sequence.
    #chksum = socket.htons(chksum)
    hdr = struct.pack("!BBH4p", msg_type, msg_code, chksum, u32)
    return hdr + payload

def make_icmp_ping(
        ident: int, seq_num: int, payload: bytes
    ) -> bytes:
    if (len(payload) > DEFAULT_PAYLOAD_SZ):
        raise ValueError(
            ("payload larger than default size limit: {}, large payload may"
             "results in IP packet fragment.").format(DEFAULT_PAYLOAD_SZ)
        )
    u32_buf = struct.pack("!HH", ident & 0xFFFF, seq_num & 0xFFFF)
    return _make_icmp_packet(
            ICMPv4Type.EchoRequest,
            0, u32_buf, payload
        )

def make_simple_ping() -> bytes:
    return make_icmp_ping(
            0 , 0, DEFAULT_PING_PAYLOAD
        )

def get_icmp_addrif(host: str, version: int) -> Addrinfo:
    """
    Return the first availiable addrinfo for ICMP connection according to
    the version hint.
    """
    addrif: Addrinfo            = None
    ai: typing.List[Addrinfo]   = None
    if  version != socket.AF_INET  and \
        version != socket.AF_INET6 and \
        version != socket.AF_UNSPEC:
        raise Exception("{} is not a valid IP version".format(version))
    try:
        # NOTE: use empty string for cross-platform.
        ai = socket.getaddrinfo(
            host, "",
            version,
            socket.SOCK_RAW,
            socket.getprotobyname("ICMP"),
            socket.AI_CANONNAME
        )
    except socket.gaierror:
        pass
    if ai is None:
        plog.error(f"Can't get addrinfo of host: {host}")
    else:
        # just use the first one.
        af, sock_type, proto, canonname, saddr = ai[0]
        #if   af == socket.AF_INET :
        #    saddr_nt = Sockaddr4
        #else:
        #    saddr_nt = Sockaddr6
        addrif = Addrinfo(
            af, sock_type, proto, canonname, saddr
        )
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
        if ver != 4:
            raise ValueError("{} is not a valid IP version".format(ver))
        v4 = HeaderStruct.IPv4.unpack(b[:20])

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


class IPv6():
    def __init__(self, b: bytes):
        ver = _get_ip_ver(b)
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
    """Simple ICMPv4 parser only for ping packets."""
    def __init__(self, b: bytes):
        # TODO: complete check
        icmpv4 = HeaderStruct.ICMPv4.unpack(b[:8])

        self.type       = icmpv4[0]
        self.code       = icmpv4[1]
        self.checksum   = icmpv4[2]
        # the following fields are actually type-dependent.
        self.id         = icmpv4[3]
        self.seq        = icmpv4[4]
        self.payload    = b[2*4:]
        return
    # TODO: implement `__repr__` method


class ICMPv6():
    def __init__(self, b: bytes):
        icmpv6 = HeaderStruct.ICMPv6.unpack(b[:8])
        # TODO: do checksum?
        self.type = icmpv6[0]
        self.code = icmpv6[1]
        self.checksum = icmpv6[2]
        # for compatiblility reason.
        self.ident = icmpv6[3]
        self.seq_num = icmpv6[4]
        self.msg_body = b[8:]
        return


def parse_packet(b: bytes) -> tuple:
    # TODO: do checksum out side IP classes.
    ver = _get_ip_ver(b)
    if   ver == 4:
        return parse_packet4(b)
    elif ver == 6:
        return parse_packet6(b)
    else:
        pass
    return

def parse_packet4(b: bytes):
    ip_pack = IPv4(b)
    if ip_pack.proto != socket.IPPROTO_ICMP:
        return
    chksum = _inet_checksum(ip_pack.payload)
    if chksum != 0:
        plog.error("Checksum error")
    icmp_pack = ICMPv4(ip_pack.payload)
    return (ip_pack, icmp_pack)

def parse_packet6(b: bytes):
    ip_pack = IPv6(b)
    if ip_pack.next_header != socket.IPPROTO_ICMP:
        return
    chksum = _inet_checksum(
        ip_pack.make_psuedo_hdr(ip_pack.payload_length) + \
        ip_pack.payload
    )
    if chksum != 0:
        plog.error("Checksum error")
    icmp_pack = ICMPv6(ip_pack.payload)
    return (ip_pack, icmp_pack)


class _PacketRecord():
    """Auxillary class for package loading and delay calculation."""
    def __init__(self):
        self.send_time      = 0.0
        self.recv_time      = float("inf")
        self.ip_pack        = None
        self.icmp_pack      = None
        self.is_echo_reply  = False
        return

    def get_delay(self) -> float:
        if self.ip_pack is not None and self.is_echo_reply is True:
            return self.recv_time - self.send_time
        return float("NaN")


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
        proto_icmp  = socket.getprotobyname("icmp")
        self.sock   = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            proto_icmp
        )
        self.sockv6 = socket.socket(
            socket.AF_INET6,
            socket.SOCK_RAW,
            _IPPRPTO_ICMPv6
        )
        self.packet         = make_simple_ping()
        self._icmp_ident    = 0
        self._addrif_cache: typing.Dict[str, Addrinfo] = dict()
        return
    
    def __del__(self):
        self.sock.close()
        return

    @property
    def icmp_ident(self):
        """An auto increment serial number."""
        self._icmp_ident += 1
        self._icmp_ident &= 0xFFFFFFFF
        return self._icmp_ident

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
        # make packets right before sending?
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

    def _send_icmp_er_pmr(
            self, pmr: _PingMultiRecord,
        ):
        pr  = _PacketRecord()
        pr.send_time = time.time()
        if pmr.addrinfo.family == socket.AF_INET:
            sock = self.sock
        else:
            # or what else can it be?
            sock = self.sockv6
        try:
            _ = sock.sendto(self.packet, pmr.addrinfo.sockaddr[:2])
            raw, _ = sock.recvfrom(DEFAULT_RCV_BUFSZ)
            ver = _get_ip_ver(raw)
            ip, icmp = parse_packet(raw)
            if (ver == 4 and ip.proto == socket.IPPROTO_ICMP) or \
               (ver == 6 and ip.next_header == _IPPRPTO_ICMPv6):
                # ensure it is ip and also icmp packet.
                is_er = (
                    icmp.type == ICMPv4Type.EchoReply or \
                    icmp.type == ICMPv6Type.EchoReply
                )
            else:
                is_er = False
            pr.recv_time        = time.time()
            pr.ip_pack          = ip
            pr.icmp_pack        = icmp
            pr.is_echo_reply    = is_er
        except socket.timeout:
            pass
        pmr.packet_record = pr
        return

    def ping_once_pmr(
            self, host: str, timeout: float=DEFAULT_TIMEOUT
        ) -> typing.Tuple[bool, float]:
        addrif = get_icmp_addrif(host, socket.AF_UNSPEC)
        if addrif is None:
            raise Exception("No addrinfo for host: {}".format(host))
        pmr = _PingMultiRecord(host, addrif)
        with _set_timeout(self.sock, timeout):
            self._send_icmp_er_pmr(pmr)
        pr = pmr.packet_record
        return (pr.is_echo_reply, pr.get_delay())

    def ping_once(
            self, host: str,
            timeout: float=DEFAULT_TIMEOUT
        ) -> typing.Tuple[float, bool]:
        """Simply ping the host."""
        dt  = 0
        suc = False
        addrif = get_icmp_addrif(host, socket.AF_UNSPEC)
        if addrif is None:
            raise Exception("No addrinfo for host: {}".format(host))
        with _set_timeout(self.sock, timeout):
            dt, _, icmpv4 = self._send_icmp_er(
                addrif.sockaddr[:2], None, None
            )
            if icmpv4 is not None and icmpv4.type == ICMPv4Type.EchoReply:
                suc = True
        return (dt, suc)

    def ping_seq(
            self, host: str, count: int,
            interval: float,
            timeout: float=DEFAULT_TIMEOUT
        ) -> typing.List[typing.Tuple[float, bool]]:
        """Ping host for `count` times with `interval` delay."""
        dt  = 0
        suc = False
        addrif = get_icmp_addrif(host, socket.AF_UNSPEC)
        if addrif is None:
            raise Exception("No addrinfo for host: {}".format(host))
        res = list()
        with _set_timeout(self.sock, timeout):
            for _ in range(count):
                dt, _, icmpv4 = self._send_icmp_er(addrif.sockaddr, None, None)
                if icmpv4 is not None and icmpv4.type == ICMPv4Type.EchoReply:
                    suc = True
                res.append((dt, suc))
                time.sleep(interval)
        return res

    def ping_seq_pmr(
            self, host: str, count: int,
            interval: float, timeout: float=DEFAULT_TIMEOUT
        ) -> typing.List[typing.Tuple[bool, float]]:
        addrif = get_icmp_addrif(host, socket.AF_UNSPEC)
        if addrif is None:
            raise Exception("No addrinfo for host: {}".format(host))
        res = list()
        pmr = _PingMultiRecord(host, addrif)
        pr: _PacketRecord = None
        with _set_timeout(self.sock, timeout):
            for _ in range(count):
                self._send_icmp_er_pmr(pmr)
                pr = pmr.packet_record
                res.append(
                    (pr.is_echo_reply, pr.get_delay())
                )
                time.sleep(interval)
        return res

    def _con_send_icmp_er(
            self, pmr_list: typing.List[_PingMultiRecord],
            timeout: float
        ) -> dict:
        """Concurrent icmp echo request sender."""
        packet_sent = 0
        # in C we'll use BST or hash table.
        addr_pmr_map = {
            pmr.addrinfo.sockaddr[0]: pmr
            for pmr in pmr_list
        }
        # TODO: add a v6 socket.
        socket_list = [self.sock, self.sockv6]
        # NOTE: maybe some day a multi socket multiping?
        # NOTE: Some issues from `multi-ping` library reported that
        #   burst ping results in packet loss, it can (probably) be eliminated
        #   by introducing a small amount of delay between each 
        #   packet dispatching.
        icmp_seq = self.icmp_ident
        # Identify each packet using echo reply message body field.
        icmp_packet = make_icmp_ping(
            0, 0, struct.pack("!L", icmp_seq & 0xFFFFFFFF)
        )
        packet = icmp_packet
        pr: _PacketRecord = None
        for pmr in pmr_list:
            ai = pmr.addrinfo
            if ai is None:
                continue
            addr = ai.sockaddr[0]
            # NOTE: this may block?
            # switch sending socket according to addrinfo version.
            #_ = self.sock.sendto(packet, ai.sockaddr)
            if  ai.family == socket.AF_INET:
                self.sock.sendto(packet, ai.sockaddr)
            elif ai.family == socket.AF_INET6:
                self.sockv6.sendto(packet, ai.sockaddr[:2])
            else:
                pass
            pr = _PacketRecord()        # new pr
            pr.send_time = time.time()
            addr_pmr_map[addr].packet_record = pr
            packet_sent += 1
            #time.sleep(SEND_DELAY)

        total_t0 = 0.0
        total_dt = 0.0

        total_t0 = time.perf_counter()

        rem_timeout = timeout
        rem_recv = packet_sent
        while True:
            t0 = time.perf_counter()
            r, _, _ = select.select(socket_list, [], [], rem_timeout)
            if r == []:
                plog.debug("select timeout")
                break
            for sock in r:
                raw, (addr, _) = sock.recvfrom(DEFAULT_RCV_BUFSZ)
                # TODO: parse packet first, then assign them to each
                #   packet_record.
                #   need to handle parse error.
                ver = _get_ip_ver(raw)
                ip, icmp = parse_packet(raw)
                # There must be a switch, but since they have the same name,
                # it's ok (for python).
                if (ver == 4 and ip.proto == socket.IPPROTO_ICMP) or \
                   (ver == 6 and ip.next_header == _IPPRPTO_ICMPv6):
                    is_er = (
                        icmp.type == ICMPv4Type.EchoReply or \
                        icmp.type == ICMPv6Type.EchoReply
                    )
                else:
                    is_er = False
                serial_n = struct.unpack("!L", icmp.payload)[0] \
                    if is_er is True else -1
                # ------
                if addr in addr_pmr_map.keys():
                    # assign packets to packet_record and set recv time.
                    pr = addr_pmr_map[addr].packet_record
                    pr.ip_pack          = ip
                    pr.icmp_pack        = icmp
                    pr.recv_time        = time.time()
                    pr.is_echo_reply    = is_er
                    # ------
                    if serial_n == icmp_seq:
                        rem_recv -= 1
                else:
                    # TODO: parse raw packet and see what happends.
                    plog.debug(f"received packet from {addr}, raw:\n{raw}")
                    plog.debug(f"sn={serial_n} seq={icmp_seq}")
                    pass
            dt = time.perf_counter() - t0
            if rem_timeout < dt:
                plog.debug(f"rem={rem_timeout}, mpdt={dt}")
                rem_timeout = 0.0
                break
            else:
                rem_timeout -= dt
            if rem_recv == 0:
                plog.debug("early out")
                # if we retrived all packet, break out early.
                break
        
        total_dt = time.perf_counter() - total_t0
        if total_dt > timeout:
            plog.debug(f"total_dt={total_dt}")

        return addr_pmr_map

    def _ping_multi(
            self, host_list: typing.List[str],
            timeout: float=DEFAULT_TIMEOUT,
            pr_callback: typing.Callable[[_PacketRecord,], typing.Any]=None,
            skip_unknown_hosts=False
        ) -> typing.List[_PingMultiRecord]:
        """
        Bottom layer of `ping_multi`, accepting a callback for preprocess.
        If callback is `None`, the raw `_PacketRecord` instance is exposed.
        """
        # host -> addr -> PacketRecord
        # PROPOSAL: An optional parameter of a dict for storing result,
        #   saving memory and construction time.
        addrif: Addrinfo = None
        # PROPOSAL: caching addrif?(ACCEPTED -> DONE)
        pmr_list = list()
        # NOTE: we need a cache expiration mechanism.
        for host in host_list:
            if host in self._addrif_cache.keys():
                addrif = self._addrif_cache[host]
            else:
                # There is (probably) no way for finer-grained control unless
                # we change the API.
                addrif = get_icmp_addrif(host, socket.AF_UNSPEC)
            pmr_list.append(
                _PingMultiRecord(host, addrif)
            )
        if skip_unknown_hosts is False:
            for pmr in pmr_list:
                if pmr.addrinfo is None:
                    raise Exception("No addrinfo for host: {}".format(pmr.host))
        
        _ = self._con_send_icmp_er( # addr_pmr_map
            pmr_list, timeout
        )
        for pmr in pmr_list:
            if pr_callback is not None:
                pmr.res = pr_callback(pmr.packet_record)
            pass
        return pmr_list

    def ping_multi(
            self, host_list: typing.List[str],
            timeout: float=DEFAULT_TIMEOUT,
            mapping: dict=None,
            skip_unknown_hosts=False
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
                pr_callback=get_delay_cb,
                skip_unknown_hosts=skip_unknown_hosts
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
