import tuntap
import header.ethernet

tap_name = "tap0"
dev = tuntap.Tuntap(tap_name)
dev.new_net_dev()
dev.set_link_up()
dev.set_route("192.168.1.0/24")
print("start capturing")


while True:
    buf = dev.blocking_read(dev.mut())
    e = header.ethernet.EthernetFields(buf)

