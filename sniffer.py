from scapy.all import *
from datetime import datetime

ap_list = []
interface = "eth0"

def get_interfaces():
    #return a list of available network interfaces
    interfaces = []
    for iface_name in sorted(ifaces.data.keys()):
        dev = ifaces.data[iface_name]

        i = name = str(dev.name).ljust(4)
        interfaces.append(i)

    return interfaces


def sniffer():
    sniff (iface = "Intel(R) Centrino(R) Advanced-N 6205",
           prn = write_packet2log, lfilter = lambda pkt: (IP in pkt and TCP in pkt))
    #sniff(iface = ["eth0", "mon0"],
    #prn = lambda pkt: "%s: %s" %(pkt.sniffed_on, pkt.summary())


def write_packet2log(packet):
    pkt_time = str (datetime.datetime.now()).split('.')[0]
    print "{} {} {} {} {} ".format(pkt_time, packet[IP].src,
                                         packet[IP].dst,
                                         packet[TCP].dport,
                                         "PASS"
                                         )




def print_packet(packet):
    ip_layer = packet.getlayer(IP)
    print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))

    print("[*] Start sniffing...")
    sniff(iface=interface, filter="ip", prn=print_packet)
    print("[*] Stop sniffing")


def PacketHandler(pkt) :

  if pkt.haslayer(Dot11):
      if pkt.type == 0 and pkt.subtype == 8:
          if pkt.addr2 not in ap_list:
              ap_list.append(pkt.addr2)
              print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)

#sniff(iface="mon0", prn = PacketHandler)





def main():

    print get_interfaces()
    print sniffer()


if __name__ == '__main__':
    main()