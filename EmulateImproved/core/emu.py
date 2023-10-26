import unicorn
from unicorn import arm64_const, arm_const, x86_const

from collections import defaultdict

from . import memory_manager
from . import decompilerapi
from . import const


class BaseEmulationEngine:
	'''
	engine - unicorn.Uc
	'''
	def __init__(self, uc: unicorn.Uc, strict: bool = False):
		self.__uc = uc

	def add_hook(self, hook_type, hook_handler):
		raise NotImplementedError
	
	def start(self):
		self.__uc

	def pre_emulation(self):
		raise NotImplementedError

	def post_emulation(self):
		raise NotImplementedError

	def setup_stackframe(self, frame_size=const.FRAME_SIZE):
		raise NotImplementedError


class Aarch64EmulationEngine(BaseEmulationEngine):
	def __init__(self):
		super().__init__()

		self.__uc = unicorn.Uc()
		self.memory_manager = memory_manager.MemoryManager(self.__engine)
		self.hooks = defaultdict(list)
		self.emulation_range = None

	def setup_stackframe(self, frame_size=const.FRAME_SIZE):
		self.__uc.mem_map(const.STACK_BASE - 4 * 0x1000, 8 * 0x1000)
		mu.reg_write(UC_ARM64_REG_SP, STACK_BASE)

		if address is not None:
			frame_size = decompilerapi.get_frame_size(address)
		else:
			frame_size = FRAME_SIZE

		sp_value = mu.reg_read(UC_ARM64_REG_SP)
		mu.mem_write(sp_value, p64(0x1122DEADBEEF3344))
		mu.mem_write(sp_value - 4, p64(0x1122DEADBEEF3344))
		mu.reg_write(UC_ARM64_REG_FP, sp_value - 8)
		mu.reg_write(UC_ARM64_REG_SP, sp_value - frame_size)