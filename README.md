# nrfdump

Python script for dumping firmware from read-back protected nRF51 chips.

The read-back protection of an nRF51 SoC protects the memory of the chip against direct read/write via SWD.
However, it does not prevent read/write access to its registers (general-purpose / stack pointer / program counter / ...).

Thus it is possible to:
1. Connect to the chip via SWD
2. Find an instruction that copies data from memory to a register (for instance `ldr r4, [r4]`)
3. Set program counter to the address of the memory-to-register copying instruction
4. Set source register to address N
5. Execute the instruction
6. Read the destination register (data copied from the memory location)
7. Increase source register (N = N + 4)
8. Repeat from 3.

nrfdump connects to OpenOCD GDB server, finds an instruction that can be used to copy a memory address into a register and dumps the memory by (ab)using this instruction.  

Please note that although nrfdump worked perfectly for me during my project, it takes an opportunistic approach, ie. there are some things which can potentially go wrong.  
They can range from the script not being able to find a usable instruction to misconfiguration of the device or even brick.  
Use at your own risk!


```
$ ./nrfdump.py 
Open On-Chip Debugger

[*] Reading RBPCONF to establish known memory address / value...
[***] RBPCONF is: 0xFFFF00FF
[*] Searching for usable instruction...
[*] pc = 0x6d0
[*] pc = 0x6d2
[*] pc = 0x6d4
[***] Known value found in register r4 for pc = 0x6d4
[*] Checking which register is the source...
[*] register: r0
[*] register: r1
[*] register: r2
[*] register: r3
[*] register: r4
[***] Found source register: r4

[***] The state of the game:
Known address: 0x10001004
Known value at the address: 0xFFFF00FF
Instruction address: 0x6d4
Register in: r4
Register out: r4

[*] Dumping memory (0x0 - 0x40000) to output file: out.bin ...
0x0: 0x000007C0
0x4: 0x000006D1
0x8: 0x000000D1
0xc: 0x000006B1
0x10: 0x00000000

[...]
```
  
  
  
This technique was earlier described in the following blog post:
  
[Firmware dumping technique for an ARM Cortex-M0 SoC](http://blog.includesecurity.com/2015/11/NordicSemi-ARM-SoC-Firmware-dumping-technique.html)
  
Forked and updated to remove dependency on telnetlib and have some speed improvements at the same time. This now requires [python-openocd](https://gitlab.zapb.de/openocd/python-openocd)