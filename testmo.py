import time

import ping

HOSTS = [
    "www.google.com",
    "www.youtube.com",
    "www.gmail.com",
    "www.example.com",
    "www.ptt.cc",
    "ptt.cc",
    "www.pixiv.net",
]

m = ping.Monitor(1.0, 0.5)
m.reg_callbacks([ping.monitor2.ping_cb,])
for host in HOSTS:
    m.subscribe(host)
time.sleep(6)
a = m.get_all()
#print(a)