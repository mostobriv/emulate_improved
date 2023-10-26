from . import decompilerapi


STACK_BASE = None
IMAGE_BASE = None

PAGE_SIZE = 0x1000
FRAME_SIZE = 0x1000

def init() -> None:
    global STACK_BASE, IMAGE_BASE
    
    bitness = decompilerapi.cpu.current_bitness()
    if bitness == 16:
        STACK_BASE = 0x7F00
    elif bitness == 32:
        STACK_BASE = 0x7FFF0000
    else: # bitness == 64:
        STACK_BASE = 0x7FFFFFFF00000000
        


    hardcoded_imagebase = decompilerapi.get_imagebase()
    if hardcoded_imagebase != 0:
        IMAGE_BASE = hardcoded_imagebase
    else:
        bitness = decompilerapi.cpu.current_bitness()
        if bitness == 16:
            IMAGE_BASE = 0
        elif bitness == 32:
            IMAGE_BASE = 0x10000000
        else: # bitness == 64
            IMAGE_BASE = 0x100000000

init()