# Ping

>  A pure python ping library.

The ping library is inspired by [MultiPing](https://github.com/romana/multi-ping) and as a practice to raw socket and ICMP/IP of my own.

## Table of Contents
- Features(#Features)
- Install(#Install)
- Example(#Example)
- Requirements(#Requirements)
- License(#License)

## Features
- Pure python implementation, no 3rd party library is required.
- class `Monitor` for periodically monitoring multiple hosts.

## Install
```=
pip install .
```

## Example
### ping once/sequecially/multiple host at once.
```=
import ping
host = "www.google.com"
timeout = 0.5
interval = 1.0
p = ping.Ping()
success, dt = p.ping_once(host, timeout=timeout)
suc_dt_list = p.ping_seq(host, timeout=timeout, interval=interval)
host_dt_map = p.ping_multi([host,], timeout=timeout)
```

### tracert
:::warning
`tracert` function is currently only work on linux.
You may need to configure firewall to enable this feature.
:::
```=
import ping
host = "www.google.com"
timeout = 0.5
max_hops = 30
route_list = ping.tracert(host, timeout, max_hops)
```

### startup monitor service
```=
import ping
hosts = [
    "www.google.com",
    "www.youtube.com",
]
timeout = 0.5
interval = 1.0
m = ping.Monitor(interval, timeout)
for host in hosts:
    m.subscribe(host)
m.resume()
# ...
pmr = m.get()
```

## Requirements
- python >= 3.6

## License
`ping` library is distributed under MIT license.
