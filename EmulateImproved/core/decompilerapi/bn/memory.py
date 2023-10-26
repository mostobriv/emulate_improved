import binaryninja
from binaryninja.enums import VariableSourceType

from typing import List, Optional

def get_byte(address: int) -> int:
    return current_view.read_int(address, 1)

def get_word(address: int) -> int:
    return current_view.read_int(address, 2)

def get_dword(address: int) -> int:
    return current_view.read_int(address, 4)

def get_qword(address: int) -> int:
    return current_view.read_int(address, 8)

def get_bytes(address: int, n: int) -> bytes:
    return current_view.read(address, n)

def get_frame_size(address: int) -> int:
    func = current_view.get_function_at(address)
    if func is not None:
        vars = [v for v in func.mlil.vars if v.source_type == VariableSourceType.StackVariableSourceType]
        highest_stack_var = min(vars, key=lambda x: x.storage)
        return abs(highest_stack_var.storage)
    
    raise NotImplementedError

def get_imagebase() -> int:
    return current_view.start

def resolve_symbol_by_name(symbol_name: str) -> Optional[int]:
    symbol = current_view.get_symbol_by_raw_name(symbol_name)
    if symbol is None:
        return None

    return symbol.address