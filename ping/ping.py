import array
import logging
import math
import operator
import os
import random
import select
import socket
import struct
import time
import typing
from collections import namedtuple
from contextlib import contextmanager
from types import SimpleNamespace

from .logger import get_logger as pget_logger
from . import ip

__all__ = [
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
        - We must admit that IPv6 is a whole lot different thing than
          old IPv4, so further clarifacation is required.
    - use `logging` than naive `print`.(DONE)
    - an option of `ping_multi`(and others) for silently handling unresolvable
      hosts.
    - investigate why sometimes `_ping_multi` got huge delay.
    - seperate class `Ping` to `ping.py`(DONE)
    - add `as_<ICMP msg type>` method for flexible data intepretation.
    - support ICMP `TimeExceed` message, or further, all icmp messages.


    <PROPOSAL>
    - asyncio version ping
    - a "no exception" version of ping.
    - substitute mutiple return value with custom namedtuple
    - Mapping ICMPv4 parse result to Enum.
    - multi-process/multi-thread version
    - support super massive ping(kind of illegal)
    - caching addrinfo results(DONE)
    - multi-socket ping
    - tracking passing routers and route pathes, emit callback when
      route changes.
"""

plog: logging.Logger = pget_logger().getChild("ping")


_IPPROTO_ICMPv6 = 58    # python win32 doesn't have this defined.


DEFAULT_TIMEOUT =   2000.0/1000.0
DEFAULT_INTERVAL =  1000.0/1000.0
DEFAULT_RCV_BUFSZ = 1024
DEFAULT_PAYLOAD_SZ = 1024   # - 20 - 2*2 - 4

IPv4_MAX_SZ = (1 << 16) - 1


Addrinfo = namedtuple(
    "Addrinfo",
    ["family", "type", "proto", "canonname", "sockaddr"]
)
Sockaddr = typing.Tuple[str, int]


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
    icmp_proto = socket.IPPROTO_ICMP if version == socket.AF_INET \
        else _IPPROTO_ICMPv6
    try:
        # NOTE: use empty string for cross-platform.
        ai = socket.getaddrinfo(
            host, "",
            version,
            socket.SOCK_RAW,
            icmp_proto,
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
def _set_timeout(sock: socket.socket, timeout: float):
    """Set timeout of the socket and restore."""
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        yield
    finally:
        # restore timeout anyway.
        sock.settimeout(old_timeout)
    return

@contextmanager
def _save_ttl(sock: socket.socket):
    old_ttl = sock.getsockopt(socket.SOL_IP, socket.IP_TTL)
    try:
        yield
    finally:
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, old_ttl)
    return

class _PacketRecord():
    """Auxillary class for package loading and delay calculation."""
    def __init__(self):
        self.send_time      = 0.0
        self.recv_time      = -math.inf # so `get_delay` works
        self.ip_pack        = None
        self.icmp_pack      = None
        self.is_echo_reply  = False
        return

    def get_delay(self) -> float:
        dt =  self.recv_time - self.send_time
        if dt < 0.0:
            return math.nan
        return dt


class _PingMultiRecord():
    """Auxiliary data carrier."""
    def __init__(self, host: str, addrif: Addrinfo):
        self.host       = host
        self.addrinfo   = addrif
        self.packet_record: _PacketRecord   = _PacketRecord()
        self.res: typing.Any                = None
        return


class Ping():
    def __init__(self):
        proto_icmp  = socket.getprotobyname("icmp")
        self.sock   = None
        self.sockv6 = None

        self.sock   = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            proto_icmp
        )
        #self.sock.bind(("0.0.0.0", 0))
        self.sockv6 = socket.socket(
            socket.AF_INET6,
            socket.SOCK_RAW,
            _IPPROTO_ICMPv6
        )
        #self.sockv6.bind(("::", 0))
        self._icmp_ident    = 0
        self._addrif_cache: \
            typing.Dict[str, typing.Tuple[Addrinfo, int]] = dict()
        self._max_age       = 300 
        return
    
    def __del__(self):
        # this prevents calling `close` on uninitialized object.
        self.sock.close()   if self.sock    is not None else ()
        self.sockv6.close() if self.sockv6  is not None else ()
        return

    @property
    def icmp_seq(self):
        """An auto increment sequence number."""
        self._icmp_ident += 1
        self._icmp_ident &= 0xFFFF
        return self._icmp_ident

    @property
    def icmp_ident(self):
        """Generate random uint16_t for identity use."""
        return random.randint(0, 0xFFFF)

    @property
    def rand_uint32(self):
        return random.randint(0, 0xFFFFFFFF)

    def _send_icmp_er_pmr(
            self, pmr: _PingMultiRecord
        ) -> int:
        ret = 0
        pr = pmr.packet_record
        pr.send_time = time.time()
        icmp_packet = None
        ping_maker = None
        if pmr.addrinfo.family == socket.AF_INET:
            sock = self.sock
            ping_maker = ip.make_icmp_ping
            
        else:
            # or what else can it be?
            sock = self.sockv6
            ping_maker = ip.make_icmpv6_ping
        ident = self.icmp_ident
        icmp_packet = ping_maker(
            ident, self.icmp_seq,
            struct.pack("!L", self.rand_uint32)
        )
        try:
            while True:
                _ = sock.sendto(icmp_packet, pmr.addrinfo.sockaddr[:2])
                raw, _ = sock.recvfrom(DEFAULT_RCV_BUFSZ)
                # TODO: write little routines to extract informations.
                if sock == self.sock:
                    ip_pack, icmp = ip.parse_packet(raw)
                    is_er = ip.is_icmp_echo_reply(raw)
                    if is_er is True:
                        res_id, _, _ = icmp.as_echo_reply4()
                else:
                    ip_pack, icmp = None, ip.ICMPv6(raw)
                    is_er = (icmp.type == ip.ICMPv6Type.EchoReply)
                    if is_er is True:
                        res_id, _, _ = icmp.as_echo_reply6()
                if is_er is True and res_id == ident:
                    break
            pr.recv_time        = time.time()
            pr.ip_pack          = ip_pack
            pr.icmp_pack        = icmp
            pr.is_echo_reply    = is_er
        except socket.timeout:
            ret = -1
            pass
        return ret

    def ping_once(
            self, host: str, timeout: float=DEFAULT_TIMEOUT
        ) -> typing.Tuple[bool, float]:
        """Ping host once."""
        addrif = get_icmp_addrif(host, socket.AF_UNSPEC)
        if addrif is None:
            raise Exception("No addrinfo for host: {}".format(host))
        pmr = _PingMultiRecord(host, addrif)
        with _set_timeout(self.sock, timeout):
            self._send_icmp_er_pmr(pmr)
        pr = pmr.packet_record
        return (pr.is_echo_reply, pr.get_delay())

    def ping_seq(
            self, host: str, count: int,
            interval: float, timeout: float=DEFAULT_TIMEOUT
        ) -> typing.List[typing.Tuple[bool, float]]:
        """Ping host for `count` times with specific interval."""
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
        # in C we'll use BST or hash table, or can we eliminate the need?
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
        icmp_seq = self.rand_uint32
        # Identify each packet using echo reply message body field.
        icmpv4_packet = ip.make_icmp_ping(
            self.icmp_ident, self.icmp_seq,
            struct.pack("!L", icmp_seq)
        )
        # FIXME: seems we need to make IPv6 header ourselves.
        icmpv6_packet = ip.make_icmpv6_ping(
            self.icmp_ident, self.icmp_seq,
            struct.pack("!L", icmp_seq)
        )
        pr: _PacketRecord = None
        for pmr in pmr_list:
            pr = pmr.packet_record
            ai = pmr.addrinfo
            if ai is None:
                continue
            addr = ai.sockaddr[0]
            # NOTE: this may block?
            # switch sending socket according to addrinfo version.
            #_ = self.sock.sendto(packet, ai.sockaddr)
            if   ai.family == socket.AF_INET:
                self.sock.sendto(icmpv4_packet, ai.sockaddr)
            elif ai.family == socket.AF_INET6:
                self.sockv6.sendto(icmpv6_packet, ai.sockaddr)
            else:
                pass
            pr.send_time = time.time()
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
                rcv_res = sock.recvfrom(DEFAULT_RCV_BUFSZ)
                raw, (addr, *_) = rcv_res
                # we can't get IPv6 header in SOCK_RAW mode.
                # TODO: handle packet is not EchoReply
                if sock == self.sock:
                    # is v4 socket
                    ip_pack, icmp = ip.parse_packet(raw)
                    is_er = ip.is_icmp_echo_reply(raw)
                    _, _, payload = icmp.as_echo_reply4()
                else:
                    # NOTE: IPv6 programming is quite different.
                    ip_pack, icmp = None, ip.ICMPv6(raw)
                    is_er = (icmp.type == ip.ICMPv6Type.EchoReply)
                    _, _, payload = icmp.as_echo_reply6()
                if is_er is False:
                    # skip those non-echoreply packets.
                    continue
                serial_n = struct.unpack("!L", payload)[0] \
                    if is_er is True else -1
                
                # ------
                if addr in addr_pmr_map.keys():
                    # assign packets to packet_record and set recv time.
                    pr = addr_pmr_map[addr].packet_record
                    pr.ip_pack          = ip_pack
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
        addrif: Addrinfo = None
        # PROPOSAL: caching addrif?(ACCEPTED -> DONE)
        pmr_list = list()
        # NOTE: we need a cache expiration mechanism.
        now = time.time()
        for host in host_list:
            if host in self._addrif_cache.keys():
                addrif, create = self._addrif_cache[host]
                if (create + self._max_age) > now:
                    addrif = get_icmp_addrif(host, socket.AF_UNSPEC)
                    self._addrif_cache[host] = (addrif, time.time())
            else:
                addrif = get_icmp_addrif(host, socket.AF_UNSPEC)
                self._addrif_cache[host] = (addrif, time.time())
            # There is (probably) no way for finer-grained control unless
            # we change the API.
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
        Ping multiple hosts at a time, return a dict of host to delay.
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

    def tracert(
            self, host: str, timeout: float, max_hops: int
        ) -> typing.List[typing.Tuple[str, str, float]]:
        # basically increase ttl from 1 until target host is reached.
        # what if we send all packages at once?

        res_list = list()
        ai = get_icmp_addrif(host, socket.AF_INET)
        assert ai is not None
        assert max_hops > 0 and max_hops <= 255
        assert ai.family == socket.AF_INET
        assert timeout > 0.0
        
        plog.debug(f"Destination is {ai.sockaddr[0]}")

        pmr = _PingMultiRecord(host, ai)
        pr = pmr.packet_record

        with _set_timeout(self.sock, timeout), _save_ttl(self.sock):
            for i in range(1, max_hops+1):
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, i)
                assert self.sock.getsockopt(
                    socket.IPPROTO_IP, socket.IP_TTL
                ) == i
                
                r = self._send_icmp_er_pmr(pmr)
                dt = pr.get_delay()
                if r == -1:
                    ret_src     = ""
                    hostname    = ""
                    dt          = math.nan
                else:
                    ret_src = ".".join(map(str, pr.ip_pack.src))
                    # FIXME: make IP leave this field raw.
                    hostname, _ = socket.getnameinfo((ret_src, 0), 0)

                triple = (hostname, ret_src, dt)
                print(
                    triple, ret_src,
                )
                res_list.append(triple)
                if ret_src == ai.sockaddr[0]:
                    plog.debug("Destination reached.")
                    break
                time.sleep(0.02)
            pass
        return res_list

