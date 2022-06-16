#!/usr/bin/env python3

'''
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                     Wireshark in python

                     Made by : GrootMe

		     NotWireshark.py
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
'''

import socket, os , argparse, random
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

    tab =[BBlue,BGreen,BCyan,BPurple,BYellow,BRed]
    rand_int = random.randint(0,5)
    print(f"""{tab[rand_int]}
  _   _           _   __          __  _                      _                      _    
 | \ | |         | |  \ \        / / (_)                    | |                    | |   
 |  \| |   ___   | |_  \ \  /\  / /   _   _ __   ___   ___  | |__     __ _   _ __  | | __
 | . ` |  / _ \  | __|  \ \/  \/ /   | | | '__| / _ \ / __| | '_ \   / _` | | '__| | |/ /
 | |\  | | (_) | | |_    \  /\  /    | | | |   |  __/ \__ \ | | | | | (_| | | |    |   < 
 |_| \_|  \___/   \__|    \/  \/     |_| |_|    \___| |___/ |_| |_|  \__,_| |_|    |_|\_\\                                                                                                                                                          
     
     {Reset}""")

    print("Press Ctrl+C to stop capturing... ")
    time.sleep(2)

    try:
        while True:
            raw_data, addr = conn.recvfrom(65635)
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
