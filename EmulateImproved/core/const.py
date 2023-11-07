from EmulateImproved.core import decompilerapi

STACK_BASE = None
IMAGE_BASE = None

PAGE_SIZE = 0x1000
FRAME_SIZE = 0x1000

LOWEST_RAW_ADDRESS = decompilerapi.lowest_address()
HIGHEST_RAW_ADDRESS = decompilerapi.highest_address()

LOWEST_VIRTUAL_FILE_BACKED_ADDRESS = None
HIGHEST_VIRTUAL_FILE_BACKED_ADDRESS = None

def init() -> None:
    global STACK_BASE
    global IMAGE_BASE
    global LOWEST_VIRTUAL_FILE_BACKED_ADDRESS
    global HIGHEST_VIRTUAL_FILE_BACKED_ADDRESS
    
    bitness = decompilerapi.get_bitness()
    if bitness == 16:
        STACK_BASE = 0x7F00
    elif bitness == 32:
        STACK_BASE = 0x7FFF0000
    else: # bitness == 64:
        STACK_BASE = 0x7FFFFFFF00000000

    hardcoded_imagebase = decompilerapi.lowest_address()
    if hardcoded_imagebase != 0:
        IMAGE_BASE = hardcoded_imagebase
        LOWEST_VIRTUAL_FILE_BACKED_ADDRESS = decompilerapi.lowest_address()
        HIGHEST_VIRTUAL_FILE_BACKED_ADDRESS = decompilerapi.highest_address()
    else:
        bitness = decompilerapi.get_bitness()
        if bitness == 16:
            IMAGE_BASE = 0
        elif bitness == 32:
            IMAGE_BASE = 0x10000000
        else: # bitness == 64
            IMAGE_BASE = 0x100000000
        
        LOWEST_VIRTUAL_FILE_BACKED_ADDRESS = IMAGE_BASE
        HIGHEST_VIRTUAL_FILE_BACKED_ADDRESS = IMAGE_BASE + decompilerapi.highest_address()

init()