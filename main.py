'''                 
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                     Wireshark in python

                     Made by : GrootMe
						main.py
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
'''

import socket,time
from PCAPFile import *
from Trame import *

#ntohs(3) = Converts the uint16_t netshort from network byte order to host byte order.
#AF_* = Address Family
#PF_* Protocol family
#AF_PACKET -> travailler sur les paquets, en prenant en compte les protocoles (TCP ou UDP)
# SOCK_RAW -> inclure les paquets bruts, qui incluent le niveau 2
# SOCK_DGRAM -> Les Paquets sans le niveau 2

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    pcap = PCAPFile("Packet.pcap")
    cpt = 1

    print("Press Ctrl+C for end... ")
    time.sleep(1)
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)

            print(f"{BWhite}\n------------- Frame n° {cpt} ------------- {Reset}")
            Trame(raw_data.hex())
            cpt += 1

    except KeyboardInterrupt:
        pcap.close()
        return 0



if __name__ == '__main__':
    main()

