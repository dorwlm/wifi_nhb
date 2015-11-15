#!/usr/bin/env python
'''
Created on Nov 13, 2015
@author: dorwlm
'''

interface='' # monitor interface
aps = {} # dictionary to store unique APs

# Channel hopper
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,15)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

def insert_ap(pkt):
    ## Done in the lfilter param
    # if Dot11Beacon not in pkt and Dot11ProbeResp not in pkt:
    #     return
    bssid = pkt[Dot11].addr3
    if bssid in aps:
        return
    p = pkt[Dot11Elt]

    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')

    ssid, channel = None, None
    crypto = set()
    while isinstance(p, Dot11Elt):
        if p.ID == 0:
            ssid = p.info
        elif p.ID == 3:
            channel = ord(p.info)
        elif p.ID == 48:
            crypto.add("WPA2")
        elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
            crypto.add("WPA")
        p = p.payload
    if not crypto:
        if 'privacy' in cap:
            crypto.add("WEP")
        else:
            crypto.add("OPN")
    print "NEW AP: %r [%s], channel %d, %s" % (ssid, bssid, channel,
                                               ' / '.join(crypto))
    aps[bssid] = (ssid, channel, crypto)
    a= aps[bssid]
    b=aps[bssid]

# Capture interrupt signal and cleanup before exiting
def signal_handler(signal, frame):
    p.terminate()
    p.join()

    print "\n-=-=-=-=-=  STATISTICS =-=-=-=-=-=-"
    print "Total APs found: %d" % len(aps)
    print "Encrypted APs  : %d" % len([ap for ap in aps if "WEP" in aps[ap][2] or "WPA" in aps[ap][2] or "WPA2" in aps[ap][2]])
    print "Unencrypted APs: %d" % len([ap for ap in aps if "OPN" in aps[ap][2]])

    sys.exit(0)

if __name__ == "__main__":
    #if len(sys.argv) != 2:
     #   print "Usage %s monitor_interface" % sys.argv[0]
        #sys.exit(1)

    interface = "wlan1" #sys.argv[1]

    # Print the program header
    print "-=-=-=-=-=-= AIROSCAPY =-=-=-=-=-=-"
    print "CH ENC BSSID             SSID"

    # Start the channel hopper
    p = Process(target = channel_hopper)
    p.start()

    # Capture CTRL-C
    signal.signal(signal.SIGINT, signal_handler)

    # Start the sniffer
    #sniff(iface=interface,prn=sniffAP)
    sniff(iface=interface, prn=insert_ap, store=False, lfilter=lambda p: (Dot11Beacon in p or Dot11ProbeResp in p))