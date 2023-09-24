import idaapi


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