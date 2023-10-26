from binaryninja import enums
from . import LITTLE_ENDIAN, BIG_ENDIAN

def current_bitness() -> int:
    bitness = current_view.arch.address_size * 8
    assert bitness in [16, 32, 64], "Currently any other bitnesses but [16, 32, 64] isn't supported"

    return bitness

def current_endianess() -> int:
    if current_view.arch.endianess == enums.Endianness.LittleEndian:
        return LITTLE_ENDIAN
    else:
        return BIG_ENDIAN
