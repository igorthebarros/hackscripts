
from scapy.all import *
import os
import sys
import signal

# URL: https://www.hackers-arise.com/post/wi-fi-hacking-creating-a-wi-fi-scanner-with-python-and-scapy

def signal_handler(signal, frame):
    print('\n====================')
    print('Exiting...')
    print('====================')
    os.system('kill -9 ' + str(os.getpid()))
    sys.exit(1)

def signal_exit(signal, frame):
    print('\n====================')
    print('Signal Exiting...')
    sys.exit(1)

def usage():
    if len(sys.argv) < 3:
        print('\nUsage:')
        print('\twifi-hacking.py -i <interface>\n')
        sys.exit(1)


def sniff_packets(packet):
    try:
        SRCMAC = packet[0].addr2
        DSTMAC = packet[0].addr1
        BSSID = packet[0].addr3
    except:
        print('Error: Could not extract MAC addresses')
        print(str(packet).encode('hex'))
        sys.exc_clear()

    try:
        SSIDSize = packet[0][Dot11Elt].len
        SSID = packet[0][Dot11Elt].info
    except:
        SSID = 'Hidden'
        SSIDSize = 0

def check_for_beacon_frame(packet):
    if packet[0].type == 0:
        ST = packet[0][Dot11].subtype
        if str(ST) == '8' and SSID != '' and DSTMAC.lower() == 'ff:ff:ff:ff:ff:ff':
            p = packet[Dot11Elt]
            cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                 "Dot11ProbResp:%Dot11ProbeResp.cap%").split('+')
            channel = None
            crypto = set()

def init_process():
    global ssid_list
    ssid_list = {}
    global signal
    s = conf.L2socket(iface=newiface)


def setup_monitor (iface):
    print('Setting up sniffing options...')
    os.system('ifconfig ' + iface + ' down')

    try:
        os.system('iwconfig ' + iface + ' mode monitor')
    except:
        print('Error: Could not set monitor mode')
        sys.exit(1)
    
    os.system('ifconfig ' + iface + ' up')
    return iface

def check_root():
    if not os.geteuid() == 0:
        print('Error: This script must be run as root')
        exit(1)

if _name_ == '_main_':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_exit)
    signal.signal(signal.SIGTSTP, signal_exit)
    
    usage()
    check_root()
    
    parameters = {sys.argv[1]: sys.argv[2]}
    if 'mon' not in str(parameters['-i']):
        newiface = setup_monitor(parameters['-i'])
    else:
        newiface = str(parameters['-i'])

    init_process()
    print('Starting Wi-Fi Sniffer!')
    print('Sniffgin on interface ' + str(newiface))
    
    sniff(iface=newiface, prn=sniff_packets, store = 0)