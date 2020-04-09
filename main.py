import tuntap

tap_name = "tap0"
dev = tuntap.Tuntap(tap_name)
dev.new_net_dev()
dev.set_link_up()
dev.set_route("192.168.1.0/24")
print("start capturing")
while True:
    buf = dev.no_blocking_read(dev.mut())
    print(len(buf))
