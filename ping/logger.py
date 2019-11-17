import logging
import sys

__all__ = []

_timefmt = "%Y-%m-%d %H:%M:%S"
_strfmt = "{name} {levelname:^7s} {asctime} {message}"
_logfile = "ping.log"


_logfmtter = logging.Formatter(_strfmt, _timefmt, "{")

_streamhdlr = logging.StreamHandler(sys.stdout)
_streamhdlr.setLevel(logging.DEBUG)
_streamhdlr.setFormatter(_logfmtter)

_filehdlr = logging.FileHandler(_logfile, encoding="utf-8")
_filehdlr.setLevel(logging.DEBUG)
_filehdlr.setFormatter(_logfmtter)

_plog = logging.getLogger("Ping")
_plog.setLevel(logging.DEBUG)

_plog.addHandler(_streamhdlr)
_plog.addHandler(_filehdlr)


def get_logger() -> logging.Logger:
    return _plog
