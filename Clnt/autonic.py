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
from subprocess import call

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

#should return interface with monitor feature that didnt tested yet
#for should die, need to use while or to change interfaces{} to something more suiteble for our needs
def find_wireless_nic():
    #will die! only for test
    '''for interface, value in interfaces.iteritems():
        print "interface: " + interface
        print "value: %s" % str(value)
        if 'Monitor' in value.keys():
            print "value is monitor"
    '''
    #try to find Wireless NIC that already configured as Monitor

    i=0
    found=False
    interface=""
    while(i<len(interfaces) and not found):
        interface = interfaces.keys()[i]
        print "checking interface: " + str(interface)
        if 'Monitor' in interfaces[interface].keys():
            print str(interface) + ": mode: Monitor"
            print "checking " +str(interface)+ " status"
            if interfaces[interface]['Monitor'] == 1:
                print str(interface) + ": status 1"
                found = True
        i = i + 1

    print "will return " + str(interface)
    if(found): return interface
    else: "will try to configure interface..."

    #try to configure interface card from the pool
    i=0
    configured = False
    while(i<len(interfaces) and not configured):
        interface = interfaces.keys()[i]
        print "checking interface: " + str(interface)
        #check more mode options
        if 'Monitor' not in interfaces[interface].keys() and not interfaces[interface]['Managed']==0:
            #change configuration
            print "will disable interface"
            call(["ifconfig",str(interface), "down"])
            try:
                Wireless(interface).setMode('Monitor')
            except ValueError:
                print "resource is busy"

            print "will enable interface"
            call(["ifconfig",str(interface), "up"])
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
        print "Automatic interface mode will being operate"
        interface = find_wireless_nic()
        print "returned interface: " + str(interface)
        #if not working correctly should change status to 0
        print "try to use this interface if not working blame dorwlm"

