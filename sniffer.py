import socket
import struct
import time
import sys
import os

__author__ = 'Elvin SEVEN Mucaj'
def clear():
    return os.system('cls' if os.name == 'nt' else 'clear')

class sniffer:
	def __init__(self):
		self.prf = {"cmd": "cmd.txt", "17": "UDP", "readFile": "z:\\news.txt", "writeFile": "output.txt", "UDP_PORT": 8012, "IP": "ip_addr"}
		self.command = '\x00L\x00A\x00J\x00M\x00E\x001\x002\x003\x004'
		self.sock, self.HOST = self.getSocket()

	def getSocket(self):
		HOST = socket.gethostbyname(socket.gethostname())
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
		s.bind((HOST,self.prf["UDP_PORT"]))
		s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
		return s, HOST

	def fileToList(self, fn):
		txtfile = open(fn, "r")
		txtlst = []
		for t in txtfile:
			txtlst.append(t.rstrip())
		txtfile.close()
		return txtlst
	
	def lineToFile(self, line, f):
		resultfile = open(f, "w")
		resultfile.write(line)
		resultfile.close()

	def run(self):
		news = []
		print "[+] Loading News File...!"
		news = self.fileToList(self.prf["readFile"])
		print "[+] Done!"
		try:
			while(True):
				data=self.sock.recvfrom(65565)
				packet=data[0]
				address=data[1]
				header=struct.unpack('!BBHHHBBHBBBBBBBB', packet[:20])
				if (header[6]==17):
					if self.prf['IP'] in address[0]:
						time.sleep(1)
						self.lineToFile(packet[28:len(packet)], self.prf['cmd'])
						lst=self.fileToList(self.prf['cmd'])
						if self.command in ''.join(lst):
							print "[+] CMD: %s FROM: %s " % (self.command, address[0])
							if news:
								self.lineToFile(news[0], self.prf["writeFile"])
								print "[+] NEWS: ", news[0]
								news.pop(0)
							else:
								print "[+] ReLoading News File...!"
								time.sleep(1)
								news = self.fileToList(self.prf["readFile"])
								print "[+] Done!"
								self.lineToFile(news[0], self.prf["writeFile"])
								print "[+] NEWS: ", news[0]
								news.pop(0)
					
		except KeyboardInterrupt:
			print "[*] Interrupted by User!"
			self.sock.close()

clear()
snifferObj = sniffer()
print "[+]", __author__	
print "[+] Local IP address:", snifferObj.HOST
snifferObj.run()
