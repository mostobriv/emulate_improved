from typing import *
from typing import Any

import unicorn

from EmulateImproved.core import decompilerapi
from EmulateImproved.core import const

class MemoryManager:
	def __init__(self, mu: unicorn.Uc, endianess="little"):
		self.mu = mu
		self.endianess = endianess

	def write_ubytelong(self, addr: int, val: int, size: int=4):
		self.mu.mem_write(addr, val.to_bytes(size, self.endianess))

	def write_byte(self, addr: int, val: int):
		self.write_ubytelong(addr, val, 1)

	def write_word(self, addr: int, val: int):
		self.write_ubytelong(addr, val, 2)

	def write_dword(self, addr: int, val: int):
		self.write_ubytelong(addr, val, 4)

	def write_qword(self, addr: int, val: int):
		self.write_ubytelong(addr, val, 8)

	def write_bytes(self, addr: int, data: bytes):
		self.mu.mem_write(addr, data)

	def read_ubytelong(self, addr: int, size: int=4) -> int:
		data = self.mu.mem_read(addr, size)
		return int.from_bytes(data, self.endianess)

	def read_byte(self, addr: int) -> int:
		return self.read_ubytelong(addr, 1)

	def read_word(self, addr: int) -> int:
		return self.read_ubytelong(addr, 2)

	def read_dword(self, addr: int) -> int:
		return self.read_ubytelong(addr, 4)
	
	def read_qword(self, addr: int) -> int:
		return self.read_ubytelong(addr, 8)

	def read_bytes(self, addr: int, size: int) -> bytes:
		return self.mu.mem_read(addr, size)
	
	def read_cstr(self, addr: int, max_size: int = 128) -> bytes:
		offset = 0
		current_byte = self.read_byte(addr)
		# FIXME: dont fucking know how to concat damn bytes
		cstr = [current_byte]

		while current_byte != 0 and offset < max_size:
			offset+= 1
			current_byte = self.mu.mem_read(addr+offset, 1)[0]
			cstr.append(current_byte) # doesn't matter what endianess we used as there is just 1 byte length
		
		return bytes(cstr[:-1])


class Registers:
	def __init__(self, regs2ucregs: Dict[str, int]) -> None:
		self.regs_translation = regs2ucregs
	
	def __getattr__(self, register_name: str) -> int:
		return self.regs_translation[register_name.upper()]


def is_file_backed_memory(address: int) -> bool:
	# address: virtual address due emulation
	print("[*] Checking if %#x (%#x) is file-backed" % (address, virtual2raw(address)))

	if const.LOWEST_RAW_ADDRESS == 0:
		# binary is PIE, so we should use our own image base address
		lowest_file_backed_loaded = const.IMAGE_BASE
		highest_file_backed_loaded = const.IMAGE_BASE + const.HIGHEST_RAW_ADDRESS
	else:
		lowest_file_backed_loaded = const.LOWEST_RAW_ADDRESS
		highest_file_backed_loaded = const.HIGHEST_RAW_ADDRESS

	return lowest_file_backed_loaded <= address and address < highest_file_backed_loaded


def handle_memory_fault(uc: unicorn.Uc, access: int, address: int, size: int, value, user_data) -> bool:
	print("[!] Memory fault at %#x (%#x)" % (address, virtual2raw(address)))
	uc.mem_map(addr2page(address), const.PAGE_SIZE)

	if is_file_backed_memory(address):
		print("[!] Memory is backed by file, hotloading virtual(%#x - %#x) raw(%#x - %#x)" % 
			(
				addr2page(address),
				addr2page(address) + const.PAGE_SIZE,
				addr2page(virtual2raw(address)),
				addr2page(virtual2raw(address)) + const.PAGE_SIZE
			)
		)

		raw_data = decompilerapi.get_bytes(addr2page(virtual2raw(address)), const.PAGE_SIZE)
		uc.mem_write(addr2page(address), raw_data)

	return True

def range2page(start: int, end: int) -> Tuple[int, int]:
	return start & ~(const.PAGE_SIZE-1), (end & ~(const.PAGE_SIZE-1)) + const.PAGE_SIZE

def addr2page(addr: int) -> int:
	return addr & ~(const.PAGE_SIZE-1)

def raw2virtual(addr: int) -> int:
	if const.LOWEST_RAW_ADDRESS <= addr and addr < const.HIGHEST_RAW_ADDRESS:
		return const.LOWEST_VIRTUAL_FILE_BACKED_ADDRESS + (addr - const.LOWEST_RAW_ADDRESS)
	else:
		return addr
	
def virtual2raw(addr: int) -> int:
	if const.LOWEST_VIRTUAL_FILE_BACKED_ADDRESS <= addr and addr < const.HIGHEST_VIRTUAL_FILE_BACKED_ADDRESS:
		return const.LOWEST_RAW_ADDRESS + (addr - const.LOWEST_VIRTUAL_FILE_BACKED_ADDRESS)
	else:
		return addr