import os 
import socket
import time

ICMP_ECHO_REQUEST = 8 

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        