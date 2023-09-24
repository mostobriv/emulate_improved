from unicorn import *
from unicorn.arm64_const import *
import idaapi

import struct

PAGE_SIZE = 0x1000
FRAME_SIZE = 0x1000

STACK_BASE = 0x8FFFF000

PROCESS_BASE = 0

def range2page(start, end):
	return start & ~(PAGE_SIZE-1), (end & ~(PAGE_SIZE-1)) + PAGE_SIZE


def setup_stack_frame(mu, address=None):
	mu.mem_map(STACK_BASE - 4 * 0x1000, 8 * 0x1000)
	mu.reg_write(UC_ARM64_REG_SP, STACK_BASE)

	if address is not None:
		frame_size = idc.get_frame_size(address)
	else:
		frame_size = FRAME_SIZE

	sp_value = mu.reg_read(UC_ARM64_REG_SP)
	mu.mem_write(sp_value, p64(0x1122DEADBEEF3344))
	mu.mem_write(sp_value - 4, p64(0x1122DEADBEEF3344))
	mu.reg_write(UC_ARM64_REG_FP, sp_value - 8)
	mu.reg_write(UC_ARM64_REG_SP, sp_value - frame_size)

def memory_load(mu, mem_start, mem_end):
	if mem_start % PAGE_SIZE != 0:
		print("[!] Memory range isn't aligned to page size (%#x), performing alignment: (%#x:%#x) -> (%#x:%#x)" 
			% (PAGE_SIZE, mem_start, mem_end, *range2page(mem_start, mem_end)))
		mem_start, mem_end = range2page(mem_start, mem_end)
	
	memory = idaapi.get_bytes(mem_start, mem_end-mem_start)
	mu.mem_map(PROCESS_BASE + mem_start, PROCESS_BASE + mem_end - mem_start)
	mu.mem_write(PROCESS_BASE + mem_start, memory)


def emulate_range(start, end):
	mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

	page_start, page_end = range2page(start, end)
	print("From %#x to %#x" % (page_start, page_end))

	setup_stack_frame(mu, address=start)

	code = idaapi.get_bytes(page_start, page_end-page_start)

	mu.mem_map(page_start, 0x1000 * 4)
	print(list(mu.mem_regions()))
	mu.mem_write(page_start, code)

	mu.emu_start(start, end+4, 0)

	return mu
