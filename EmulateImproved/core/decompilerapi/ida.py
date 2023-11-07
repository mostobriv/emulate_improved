from typing import *

import idaapi
import idc


def get_byte(address: int) -> int:
	return idaapi.get_byte(address)

def get_word(address: int) -> int:
	return idaapi.get_word(address)
	
def get_dword(address: int) -> int:
	return idaapi.get_dword(address)
	
def get_qword(address: int) -> int:
	return idaapi.get_qword(address)

def get_bytes(address: int, n: int) -> bytes:
	return idaapi.get_bytes(address, n)

def lowest_address() -> int:
	return idaapi.cvar.inf.min_ea

def highest_address() -> int:
	return idaapi.cvar.inf.max_ea

def get_endianess() -> Literal["little", "big"]:
	inf = idaapi.get_inf_structure()
	if inf.is_be():
		return "big"
	else:
		return "little"

def get_arch() -> Literal["arm", "x86"]:
	info = idaapi.get_inf_structure()
	if info.procname.lower() == "arm":
		return "arm"
	else:
		raise NotImplementedError("%s architecture isn't supported")

def get_bitness() -> Literal[16, 32, 64]:
	info = idaapi.get_inf_structure()
	if info.is_64bit():
		return 64
	elif info.is_32bit():
		return 32
	else:
		return 16
	
def get_func_frame_size(address: int) -> int:
	return idc.get_frame_size(address)