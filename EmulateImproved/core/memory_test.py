import unittest

import unicorn
from unicorn.unicorn_const import UC_ARCH_AMR64, UC_MODE_LITTLE_ENDIAN, UC_MODE_BIG_ENDIAN 
from unicorn.arm64_const import UC_MODE_ARM

class TestMemoryManager(unittest.TestCase):
	def test_read_byte(self):
		uc = unicorn.Uc(unicorn.unicorn_const.UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
		


if __name__ == "__main__":
	unittest.main()