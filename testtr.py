import ping

p = ping.Ping()
a = p.tracert("ptt.cc", 0.1, 30)
print(len(a))
#print(a)