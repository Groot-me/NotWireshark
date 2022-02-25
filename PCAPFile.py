#!/usr/bin/env python3

'''
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
                     Wireshark in python

                     Made by : GrootMe

		     Write .pcap file
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
'''

from struct import pack
import time
from Trame import *

class PCAPFile:
    def __init__(self,filename):
        self.fp = open(filename,"wb")
        header = pack('!IHHiIII',0xa1b2c3d4,2,4,8,8,65535,1)
        self.fp.write(header)


    def write(self,data):
        seconds, mseconds =[int(part) for part in str(time.time()).split('.')]
        length = len(data)
        message = pack('!IIII', seconds, mseconds, length, length)
        self.fp.write(message)
        self.fp.write(data)



    def close(self):
        self.fp.close()
