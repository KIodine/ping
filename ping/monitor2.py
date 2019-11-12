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
    rwlock
)

__all__ = [
    "Monitor",
]

"""Providing a framework for flexible ping-based monitoring."""

"""
TODO:
    - ...
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
class Code(enum.Enum):
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
        with self.cb_lock:
            self.callbacks.extend(callback_list)
        return len(callback_list)

    def subscribe(self, host: str):
        self.sub_msg_q.put(
            (Code.SUB, host)
        )
        return
    
    def cancel(self, host: str):
        self.sub_msg_q.put(
            (Code.UNSUB, host)
        )
        return
    
    def get(self, block=True, timeout=None):
        try:
            res = self.res_queue.get(block=block, timeout=timeout)
        except:
            raise
        else:
            self.res_queue.task_done()
        return res
    
    def get_all(self) -> typing.List:
        res_list    = list()
        res         = None
        try:
            while True:
                res = self.res_queue.get_nowait()
                res_list.append(res)
        except queue.Empty:
            pass
        return res_list

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
        while True:
            # FIXME: loop until messeges are digested.
            while not self.sub_msg_q.empty() or len(self.sub_set) == 0:
                # if we got messege or no host to monitor
                # assuming it is fast enough.
                code, host = self.sub_msg_q.get()
                if code == Code.SUB:
                    self.sub_set.add(host)
                elif code == Code.UNSUB:
                    try:
                        self.sub_set.remove(host)
                    except KeyError:
                        # just ignore it
                        pass
                # TODO: implement `PAUSE` and `RESUME`
                else:
                    pass
                self.sub_msg_q.task_done()
            t0 = time.time()
            pmr_list = self._ping._ping_multi(
                self.sub_set, timeout=self.scan_timeout
            )
            for pmr in pmr_list:
                # let `_proprocd` handle it.
                self.pp_queue.put(pmr)
            dt = time.time() - t0
            if self.scan_interval < dt:
                # minimum scan interval
                print(f"scan_interval={self.scan_interval} dt={dt}")
                dt = self.scan_interval * 0.1
            time.sleep(self.scan_interval - dt)
            #del pmr_list
        return


def ping_cb(pmr: ip._PingMultiRecord):
    """Prints typical ping output."""
    print(
        ("{:15.2f} | From {:15s}({:16s}):"
         " bytes={} ident={:5} TTL={} dt={:.5f}").format(
            time.time(),
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
