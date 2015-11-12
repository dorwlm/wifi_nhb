#!/usr/bin/env python
'''
Created on Nov 10, 2015
Module purpose: 1.find right interface to monitor APs around.
                2.configure interface into monitor mode.
@author: dorwlm
'''

from pythonwifi.iwlibs import *
import re
from optparse import OptionParser
import sys

#store all Wireless NIC
interfaces = {}

#fetch all wireless network interface cards and their mode.
def fetch_wireless_cards():
    pattern = re.compile("wlan.")
    for interface in getNICnames():
        if(pattern.match(interface)):
            configuration={}
            configuration[Wireless(interface).getMode()]=1
            interfaces[interface] = configuration

    #print interfaces

def find_wireless_nic():
    for interface, value in interfaces.iteritems():
        print "interface: " + interface
        print "value: %s" % str(value)
        if 'Monitor' in value.keys():
            print "value is monitor"
    ######################################### - do!!
    print "###################while####################"
    i=0
    found=False
    while(i<len(interfaces)):
        interface = interfaces.keys()[i]
        #print interface
        if 'Monitor' in interfaces[interface].keys():

        i=i+1

if __name__ == "__main__":

    parser = OptionParser(usage="%prog [-i] <Interface> [-v] [-l]", version="%prog 1.0")
    parser.add_option("-i", "--interface", type="string", dest="interface", default="",
                      help="Specify wireless interface card to work with, otherwise will try automatically",
                      metavar="Interface")
    parser.add_option("-v", "--verbose", default=False, action="store_true", dest="verbose",
                      help="Verbose, quiet by default")
    parser.add_option("-l", "--list", action="store_true", default=False, dest="list", help="List available Wireless NICS")

    (options, args) = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    fetch_wireless_cards()

    if len(interfaces) == 0:
        print "ERROR: There is no Wireless Nic adapter connected."
        print "       Please connect Wireless NIC able to monitor"
        sys.exit(0)

    if not options.interface:
        #automatically mode
        find_wireless_nic()


    #print "checking interface %s" % options.interface

    #print "verbose %s" % options.verbose

