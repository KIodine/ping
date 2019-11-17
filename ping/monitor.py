import contextlib
import enum
import queue
import statistics
import sys
import threading
import traceback
import time
import typing

from . import (
    ip,
)

__all__ = [
    "Monitor",
]

"""Providing a framework for flexible ping-based monitoring."""

"""
TODO:
    - 

PROPOSAL:
    - add a option/opcode for purging/close res_queue.
"""

"""
possible scenario:
    1. creating a monitor instance, collect results in arbitrary timing.
    2. creating a monitor instance, register callback(s) and run it as daemon.

provisional process models:
    1. ping results -> preprocess results -> result queue
    2. ping results -> callback -> result queue
    for python: void (*cb)(_PacketRecord*) # python has `functools.partial`.
    for C:      void (*cb)(void*, _PacketRecord*)
    one can pass a callback for remote report, database recording, dump csv and
    json ... etc.
"""

# MNTD_CTL_<code>
class Opcode(enum.Enum):
    SUB     = enum.auto()
    UNSUB   = enum.auto()
    PAUSE   = enum.auto()
    RESUME  = enum.auto()


class Monitor():
    def __init__(self, scan_interval: float, scan_timeout: float):
        # TODO: limit interval and timeout
        self._is_monitoring = False
        self.scan_interval  = scan_interval
        self.scan_timeout   = scan_timeout
        self.sub_msg_q      = queue.Queue()  # passing sub/unsub msgs.
        self.pp_queue       = queue.Queue()
        self.res_queue      = queue.Queue()  # store ping results
        self.cb_lock        = threading.Lock()
        self.sub_set        = set()
        #self.notify_lock    = threading.Lock()
        #self.sub_notify     = threading.Condition(self.notify_lock)
        self._ping          = ip.Ping()
        self.callbacks      = list()
        # starts daemons.
        self._mntd = threading.Thread(target=self._monitord, daemon=True)
        self._prpd = threading.Thread(target=self._preprocd, daemon=True)
        self._mntd.start()
        self._prpd.start()
        return
    
    @property
    def is_monitoring(self) -> bool:
        return self._is_monitoring

    def reg_callbacks(self, callback_list: typing.List[typing.Callable]):
        """Register callbacks for preprocessing generated results."""
        with self.cb_lock:
            self.callbacks.extend(callback_list)
        return len(callback_list)

    def subscribe(self, host: str):
        """Add host into monitor list."""
        self.sub_msg_q.put(
            (Opcode.SUB, host)
        )
        return
    
    def cancel(self, host: str):
        """Remove host from monitor list."""
        self.sub_msg_q.put(
            (Opcode.UNSUB, host)
        )
        return
    
    def get(self, block=True, timeout=None):
        """Retrive one monitor results."""
        try:
            res = self.res_queue.get(block=block, timeout=timeout)
        except:
            raise
        else:
            self.res_queue.task_done()
        return res
    
    def get_all(self) -> typing.List:
        """Retrive all results from queue."""
        res_list    = list()
        res         = None
        try:
            while True:
                res = self.res_queue.get_nowait()
                self.res_queue.task_done()
                res_list.append(res)
        except queue.Empty:
            pass
        return res_list

    def pause(self):
        """Stops monitor temporary."""
        self.sub_msg_q.put(
            (Opcode.PAUSE, "")
        )
        return
    
    def resume(self):
        """Start/restart monitor service."""
        self.sub_msg_q.put(
            (Opcode.RESUME, "")
        )

    @contextlib.contextmanager
    def hold_on(self):
        """Temporary stop monitor service in a context."""
        self.pause()
        try:
            yield
        except:
            raise
        finally:
            if self.is_monitoring:
                self.resume()
        return

    def _preprocd(self):
        """Process returned result if callback(s) is set."""
        # though python does not capable of multi-threading, cutting job
        # like this may increase the flexibility of futher programming project.
        while True:
            pmr = self.pp_queue.get()
            try:
                # pass `pmr`(_PingMultiRecord) to each callback.
                with self.cb_lock:
                    for cb in self.callbacks:
                        cb(pmr)
                    pass
            except:
                # TODO: more verbose exception handling, ex:
                #   - function name
                #   - exception type
                pass
            finally:
                self.pp_queue.task_done()
                self.res_queue.put(pmr)
        return

    def _monitord(self):
        """Ping hosts periodically, put results in `res_queue`"""
        t0 = 0.0
        dt = 0.0
        put_t0 = 0.0
        put_dt = 0.0
        while True:
            # FIXME: loop until messeges are digested.
            while (not self.sub_msg_q.empty()) or\
                  (len(self.sub_set) == 0)     or\
                  not self.is_monitoring:
                # if we got messege or no host to monitor
                # assuming it is fast enough.
                code, host = self.sub_msg_q.get()
                if   code == Opcode.SUB:
                    self.sub_set.add(host)
                elif code == Opcode.UNSUB:
                    try:
                        self.sub_set.remove(host)
                    except KeyError:
                        # just ignore it
                        pass
                # TODO: implement `PAUSE` and `RESUME`
                elif code == Opcode.PAUSE:
                    self._is_monitoring = False
                elif code == Opcode.RESUME:
                    self._is_monitoring = True
                else:
                    pass
                self.sub_msg_q.task_done()
            t0 = time.perf_counter()
            pmr_list = self._ping._ping_multi(
                self.sub_set, timeout=self.scan_timeout
            )
            dt = time.perf_counter() - t0
            put_t0 = time.perf_counter()
            for pmr in pmr_list:
                # let `_preprocd` handle it.
                self.pp_queue.put(pmr)
            put_dt = time.perf_counter() - put_t0
            # FIXME: why sometimes `dt` is much greater than
            #        `self.scan_timeout`?
            if self.scan_interval < dt:
                # minimum scan interval
                print(
                    (f"scan_interval={self.scan_interval} dt={dt},"
                     f"put_dt={put_dt}")
                )
                dt = self.scan_interval * 0.1
            time.sleep(self.scan_interval - dt)
            #del pmr_list
        return


def ping_cb(pmr: ip._PingMultiRecord):
    """Prints typical ping output."""
    print(
        ("From {:15s}({:16s}):"
         " bytes={} ident={:5} TTL={} dt={:.5f}").format(
            pmr.addrinfo.sockaddr[0],
            pmr.host,
            len(pmr.packet_record.icmp_pack.payload),
            pmr.packet_record.ip_pack.ident,
            pmr.packet_record.ip_pack.ttl,
            (pmr.packet_record.recv_time-pmr.packet_record.send_time),
        )
    )
    sys.stdout.flush()
    return
