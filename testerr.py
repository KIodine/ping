import struct

import ping

err_datas = [
    b'E\x00\x00\x1e\xd2I\x00\x00\x80\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01\x00\x00\xa2\xfa\x1c\x05\x00\x00A\x00',
    b'E\x00\x00\x1e\xcda\x00\x00\x80\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01\x00\x00F\xe7x\x18\x00\x00A\x00',
    b'E\x00\x00\x1e\xcep\x00\x00\x80\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01\x00\x00\xb2\xd5\x0c*\x00\x00A\x00',
]

# it seems that windows(at least on Win10-1903) zeros `checksum` field when
# sending icmp reply to `localhost`.

chksm_base = 4*2+2
for d in err_datas:
    checksum = d[chksm_base: chksm_base+2]
    print(struct.unpack("H", checksum))

    print(
        struct.unpack("!B", d[0:1])[0] >> 4
    )
    print(ping.ip._inet_checksum(d[:20]))

#ipv4 = ping.IPv4(err_data)

print("---")
a = ping.ip.make_simple_ping()
print(ping.ip._inet_checksum(a))