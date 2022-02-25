#!/usr/bin/env python3

'''
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                     Wireshark in python

                     Made by : GrootMe

		     NotWireshark.py
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
'''

import socket, os
from PCAPFile import *
from Trame import *

# ntohs(3) = Converts the uint16_t netshort from network byte order to host byte order.
# AF_* = Address Family
# PF_* Protocol family
# AF_PACKET -> work on packets, taking into account the protocols (TCP or UDP)
# SOCK_RAW -> include raw packages, which include level 2
# SOCK_DGRAM -> packages without level 2

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    pcap,name_file = Create_pcapfile()

    cpt = 1

    print("Press Ctrl+C to stop capturing... ")
    time.sleep(1)

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)

            print(f"{BWhite}\n------------- Frame n° {cpt} ------------- {Reset}")
            Trame(raw_data.hex())
            cpt += 1

    except KeyboardInterrupt:
        print(Reset)
        print(f"{BWhite}The file {name_file} was created here: /root/NotWireshark/ " )
        pcap.close()
        return 0


def Create_pcapfile():

    t = time.localtime()
    current_time = time.strftime(f"%m-%d-%Y_%H:%M:%S", t)

    try:
        os.system("cd /root/NotWireshark/ 2> /dev/null")
        pcap = PCAPFile(f"/root/NotWireshark/notwireshark_{current_time}.pcap")

    except:
        os.mkdir("/root/NotWireshark")
        pcap = PCAPFile(f"/root/NotWireshark/notwireshark_{current_time}.pcap")

    return pcap, f"notwireshark_{current_time}.pcap"

if __name__ == '__main__':
    main()
