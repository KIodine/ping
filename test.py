import ping

HOSTS = [
    "www.google.com",
    "www.gmail.com",
    "www.youtube.com",
    "www.ptt.cc",
    "www.example.com"
]

f = open("ipexample.bin", "rb")
test = f.read()

ipv4 = ping.IPv4(test)
icmpv4 = ping.ICMPv4(ipv4.payload)

print(ipv4.src, ipv4.dst, ipv4.rem, ipv4.size)
print(icmpv4.payload)

a = ping.ip.make_simple_ping()
icmp2 = ping.ICMPv4(a)
print("checksum: ", ping.ip._inet_checksum(a))

p = ping.Ping()
suc, dt = p.ping_once("www.google.com", 0.5)
print(suc, dt)

suc, dt = p.ping_once_pmr("www.google.com", 0.5)
print(suc, dt)

a = p.ping_seq("www.google.com", 4, 0.2, 0.6)
print(a)

a = p.ping_multi(HOSTS)
print(
    "\n".join(
        [
            f"{host:18s}: {delay:.6f}"
            for host, delay in a.items()
        ]
    )
)
#print(a)