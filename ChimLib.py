import sys, os, time
import socket, telnetlib
import hashlib, random
from struct import pack, unpack
from subprocess import Popen, PIPE
from threading import Thread

try: import paramiko
except: pass

class ChimCalc():
	## arch in (x86, x86-64)
	## endian in < , >
	def __init__(self, **kwargs):
		self.arch = 'x86'
		self.endian = '<'
		for key, value in kwargs.iteritems():
			key = key.lower()
			if key=='arch':
				if value not in ('x86', 'x86-64'): raise Exception("[x] Wrong arch!")
				self.arch = value
			elif key=='endian':
				if value not in ('<', '>'): raise Exception("[x] Wrong endian type!")
				self.endian = value

	## Pack / Unpack value
	_p32 = lambda self, value, endian: pack(endian + 'I', value)
	_up32 = lambda self, value, endian: unpack(endian + 'I', value)[0]
	_p64 = lambda self, value, endian: pack(endian + 'Q', value)
	_up64 = lambda self, value, endian: unpack(endian + 'Q', value)[0]

	def pack(self, value, arch = None, endian = None):
		if arch == None: arch = self.arch
		if endian == None: endian = self.endian
		if arch not in ('x86', 'x86-64'): raise Exception("[x] Wrong arch!")
		if endian not in ('<', '>'): raise Exception("[x] Wrong endian type!")
		if arch=='x86': return self._p32(value, endian)
		else: return self._p64(value, endian)

	def unpack(self, value, arch = None, endian = None):
		if arch == None: arch = self.arch
		if endian == None: endian = self.endian
		if type(value) != str: raise Exception("[x] Input must be string!")
		if arch not in ('x86', 'x86-64'): raise Exception("[x] Wrong arch!")
		if endian not in ('<', '>'): raise Exception("[x] Wrong endian type!")

		MAXBYTE = (4,8)[arch == 'x86-64']
		if len(value) > MAXBYTE: value = value[:MAXBYTE]
		if len(value) < MAXBYTE:
			if endian == '<': value = value.ljust(MAXBYTE, '\x00')
			else: value = value.rjust(MAXBYTE, '\x00')

		if arch == 'x86': return self._up32(value, endian)
		else: return self._up64(value, endian)

	## Undefine binary function
	def rol(self, val, r_bits, max_bits = None):
		if max_bits == None:
			if self.arch == 'x86': max_bits = 32
			elif self.arch == 'x86-64': max_bits = 64
		return (val << r_bits%max_bits) & (2**max_bits-1) | ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
 
	def ror(self, val, r_bits, max_bits = None):
		if max_bits == None:
			if self.arch == 'x86': max_bits = 32
			elif self.arch == 'x86-64': max_bits = 64
		return ((val & (2**max_bits-1)) >> r_bits%max_bits) | (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

	## Undefine string function
	def xor(self, str1, str2, repeat = True):
		st = ""
		for i in range(max(len(str1), len(str2))):
			if repeat:
				st += chr(ord(str1[i%len(str1)]) ^ ord(str2[i%len(str2)]))
			else:
				if i >= len(str1): st += str2[i]
				elif i >= len(str2): st += str1[i]
				else: st += chr(ord(str1[i]) ^ ord(str2[i]))
		return st

	def xxd(self, stream):
		_str = ""
		i = 0
		for i,s in enumerate(list(stream)):
			if i%16 == 0: print "%07x:" % i,
			print "%02x" % ord(s),
			_str += s if( ord(s) in range(0x20,0x7f) ) else '.'
			if (i+1)%8 == 0: print '',
			if (i+1)%16 == 0:
				print "|  %s" % _str
				_str = ""
		if (i+1)%16 != 0:
			print "   "*(16-((i%16)+1)),
			if (16-((i%16)+1)) > 8: print '',
			print "|  %s" % _str

	## hash function
	def md5(self, st, digest = False):
		m = hashlib.md5(st)
		if digest: return m.digest()
		else: return m.hexdigest()

	def sha1(self, st, digest = False):
		m = hashlib.sha1(st)
		if digest: return m.digest()
		else: return m.hexdigest()

	## FMT calc
	def fmt_minus(self, value1, value2, nbyte = 1):
		n = 0x100**nbyte
		res = (value2%n) - (value1%n)
		if res < 0: res += n
		return res

	def randstr(self, n):
		st = ""
		for i in range(n):
			k = random.randint(0x20,0x7d)
			if k not in [0x00, 0x0a, 0x0b, 0x0d, 0x20]:
				st += chr(k)
		return st

class ChimPwn():
	def __init__(self, **kwargs):
		self.debug = True
		self.host = "localhost"
		self.port = 9999
		self.sock = None
		self.proc = None
		self.ssh = None
		self.timewait = 1
		for key, value in kwargs.iteritems():
			key = key.lower()
			if key == 'host': 
				if type(value) != str: raise Exception("[x] Host must be string!")
				self.host = value
			elif key == 'port':
				if type(value) != int or value<0 or value>65535: raise Exception("[x] Port must be number in range 0-65535")
				self.port = value
			elif key == 'debug':
				self.debug = value
			elif key == 'binary':
				if type(value) != str: raise Exception("[x] Filename must be string!")
				if not os.path.exists(value): raise Exception("[x] File not found!")
				self.binary = value
			elif key == 'username':
				if type(value) != str: raise Exception("[x] Username must be string!")
				self.username = value
			elif key == 'password':
				if type(value) != str: raise Exception("[x] Password must be string!")
				self.password = value
			elif key == 'timewait':
				if type(value) != int: raise Exception("[x] Timewait must be number!")
				self.timewait = value

	def _log(self, msg, debug = None):
		if debug == None: debug = self.debug
		if debug: print msg

	def connect(self, meepwn = 'remote', debug = None):
		self.meepwn = meepwn
		if self.meepwn == 'ssh':
			if 'paramiko' not in sys.modules: raise Exception("[x] Install paramiko module for ssh")
			self.sshclient = paramiko.SSHClient()
			self.sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			self.sshclient.connect(self.host, self.port, username=self.username, password=self.password)
			self.ssh = self.sshclient.invoke_shell()
			self._log("[+] SSH Connect (%s:%d)" % (self.host, self.port), debug)
		elif self.meepwn == 'local':
			self.proc = Popen("./%s" % self.binary, stdin=PIPE, stdout=PIPE, shell=False)
			self._log("[+] Open process PID %d" % self.proc.pid, debug)
		elif self.meepwn == 'remote':
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.connect((self.host, self.port))
			self._log("[+] Connect (%s:%d)" % (self.host, self.port), debug)

	def _stdout(self):
		while self.islocal: 
			sys.stdout.write(self.proc.stdout.read(1))
			sys.stdout.flush()
	def _stdin(self):
		while self.islocal: self.proc.stdin.write(raw_input() + '\n')
	def interact(self, msg = "Shell", debug = None):
		if self.meepwn == 'ssh':
			if self.ssh == None: raise Exception("[x] No ssh connection!")
			self._log("[+] SSH %s" % msg, debug)
			while not self.ssh.closed:
				time.sleep(self.timewait)
				while self.ssh.recv_ready():
					sys.stdout.write(self.ssh.recv(4096))
					sys.stdout.flush()
				self.ssh.send(raw_input() + '\n')
		elif self.meepwn == 'local':
			if self.proc == None: raise Exception("[x] No process!")
			self._log("[+] Local %s" % msg, debug)
			self.islocal = True
			Thread(target=self._stdout).start()
			Thread(target=self._stdin).start()
			self.proc.wait()
			time.sleep(self.timewait)
			self.islocal = False
		elif self.meepwn == 'remote':
			if self.sock == None: raise Exception("[x] No connection!")
			self._log("[+] Remote %s" % msg, debug)
			t = telnetlib.Telnet()
			t.sock = self.sock
			t.interact()

	def close(self, debug = None):
		if self.meepwn == 'ssh':
			if self.ssh == None: raise Exception("[x] No ssh connection!")
			self._log("[+] SSH Disconnect", debug)
			self.ssh.close()
		if self.meepwn == 'local':
			if self.proc == None: raise Exception("[x] No process!")
			self._log("[+] Kill process", debug)
			self.proc.kill()
		elif self.meepwn == 'remote':
			if self.sock == None: raise Exception("[x] No connection!")
			self._log("[+] Disconnect", debug)
			self.sock.close()

	def send(self, msg, debug = None):
		if self.meepwn == 'ssh':
			if self.ssh == None: raise Exception("[x] No ssh connection!")
			self.ssh.send(msg)
		elif self.meepwn == 'local':
			if self.proc == None: raise Exception("[x] No process!")
			self.proc.stdin.write(msg)
		elif self.meepwn == 'remote':
			if self.sock == None: raise Exception("[x] No connection!")
			self.sock.send(msg)
		self._log("[+] Send %d bytes\n%s" % (len(msg), repr(msg)), debug)

	def recv(self, msize = 4096, debug = None):
		if self.meepwn == 'ssh':
			if self.ssh == None: raise Exception("[x] No ssh connection!")
			msg = self.ssh.recv(msize)
			self._log("[+] Recv %d bytes\n%s" % (len(msg), repr(msg)), debug)
		elif self.meepwn == 'local':
			msg = self.recv_until(("at this time, i still dont know how to stop receiving when stdout of process is empty"), debug)
		elif self.meepwn == 'remote':
			if self.sock == None: raise Exception("[x] No connection!")
			msg = self.sock.recv(msize)
			self._log("[+] Recv %d bytes\n%s" % (len(msg), repr(msg)), debug)
		return msg

	def recv_full(self, debug = None):
		if self.meepwn == 'ssh':
			if self.ssh == None: raise Exception("[x] No ssh connection!")
			msg = ""
			while self.ssh.recv_ready():
				msg += self.ssh.recv(4096)
			self._log("[+] Recv %d bytes\n%s" % (len(msg), repr(msg)), debug)
		elif self.meepwn == 'local':
			msg = self.recv_until(("at this time, i still dont know how to stop receiving when stdout of process is empty"), debug)
		elif self.meepwn == 'remote':
			msg = ""
			while True:
				data = self.sock.recv(4096)
				msg += data
				if len(data)<4096:  break
			self._log("[+] Recv %d bytes\n%s" % (len(msg), repr(msg)), debug)
		return msg
	 
	def recv_until(self, arrMsg, debug = None):
		if self.meepwn == 'ssh':
			if self.ssh == None: raise Exception("[x] No ssh connection!")
		elif self.meepwn == 'local':
			if self.proc == None: raise Exception("[x] No process!")
		elif self.meepwn == 'remote':
			if self.sock == None: raise Exception("[x] No connection!")
		if type(arrMsg) not in (list, tuple, str):
			raise Exception("[x] arrMsg must be list or tuple!\nEx: ('123', ...) or ['123', ...]")
		if type(arrMsg)==str: arrMsg = [arrMsg]
		if debug == None: debug = self.debug
		if debug: print "[+] Recv"
		msg = ""
		while True:
			for m in arrMsg:
				if msg.endswith(m):
					print ""
					if debug: print 
					return msg
			if self.meepwn == 'ssh': c = self.ssh.recv(1)
			elif self.meepwn == 'local': c = self.proc.stdout.read(1)
			elif self.meepwn == 'remote': c = self.sock.recv(1)
			msg += c
			if debug:
				sys.stdout.write(repr(c)[1:-1])
				sys.stdout.flush()


def ChimHelp():
	print '''Python Library
	Name:			ChimPwn Lib
	Version:		1.1
	Author:			trichimtrich
	Blog:			http://trich.im
	Twitter:		https://twitter.com//trichimtrich

ChangeLog
	Ver1.0
		+ Pack/Unpack number
		+ Rotate bitwise
		+ Xor strings
		+ Communicate with socket only
		
	Ver1.1
		+ Add hash functions
		+ Simple format string calculator
		+ Safe random string (without specific chars)
		+ Communicate with subprocess
		+ Communicate with SSH

Structure
	Class: ChimCalc - quick calculator, use for pwning
	Class: ChimPwn - socket/ssh/process communicate 

ChimCalc
	c = ChimCalc(arch in ['x86', 'x86-64'], endian in ['<', '>'])
	c.pack(value, arch = None, endian = None): 
	c.unpack(value, arch = None, endian = None):
	c.rol(value, r_bits, max_bits = None)
	c.ror(value, r_bits, max_bits = None)
	c.xor(string1, string2, repeat = True)
	c.xxd(stream_to_hex_dump)
	c.md5(st, digest = False)
	c.sha1(st, digest = False)
	c.fmt_minus(value1, value2, nbyte = 1)
	c.randstr(num)

ChimPwn
	p = ChimPwn(host = 'localhost', port = 9999, debug = True, binary = 'filename', username = 'ssh', password = 'password', timewait = 1)
	p.connect(meepwn in ['remote', 'ssh', 'local'], debug = None)
	p.close(debug = None)
	p.interact(msg = "Shell", debug = None)
	p.send(msg, debug = None)
	p.recv(msize = 4096, debug = None)
	p.recv_full(debug = None)
	p.recv_until(arrMsg = [string1, string2, ...], debug = None)'''

if __name__=="__main__": ChimHelp()
