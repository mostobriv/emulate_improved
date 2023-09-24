import struct

p64 = lambda x: struct.pack("Q", x)
p32 = lambda x: struct.pack("I", x)
p16 = lambda x: struct.pack("H", x)