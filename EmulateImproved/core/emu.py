from typing import *

import unicorn
from unicorn import arm64_const, arm_const, x86_const

from collections import defaultdict
from collections.abc import Callable

from EmulateImproved.core import decompilerapi
from EmulateImproved.core import memory
from EmulateImproved.core import const
from EmulateImproved.core import util
from EmulateImproved.core import logger

from .memory import raw2virtual


def emulate_function(function_addr: int, concrete_arguments: List[Any]=None) -> None:
	"""Emulate function api.
	
	Parameters
	----------
	function_addr : int
		Functions in-db address (address in decompiler, it may change if current binary is PIE)
	concrete_arguments: list, optional
		List of concrete arguments and their storages (you can change it anytime
		with pre_emulation hook).
	
	"""
	emu = Aarch64EmulationEngine()
	
	arguments = decompilerapi.get_formal_function_arguments(function_addr)
	if len(arguments) != 0:
		raise NotImplementedError("Functions with any arguments not yet supported")
	
	lowest_addr, highest_addr = decompilerapi.function_range(function_addr)
	lowest_addr_aligned, highest_addr_aligned = memory.range2page(lowest_addr, highest_addr)

	emu.__uc.mem_map(0x10000, 0x1000) # TODO: consider setting (READ | EXEC) permission on this trampoline

	if raw2virtual(function_addr) % 4 != 0:
		raise NotImplementedError("Addresses non-aligned to 4 bytes not yet supported")

	endianess = decompilerapi.get_endianess()

	if (raw2virtual(function_addr) - 0x10000) <= 0x10000000:
		offset = (raw2virtual(function_addr) - 0x10000) >> 2
		emu.__uc.mem_write(0x10000, (0x94000000 | offset).to_bytes(4, endianess)) 	# BL 0x...
	else:
		# TODO: better check unspoiled registers for this call and use one of them
		emu.__uc.reg_write(arm64_const.UC_ARM64_REG_X17, raw2virtual(function_addr) - 0x10000)
		emu.__uc.mem_write(0x10000, (0xd63f0000 | (17 << 5)).to_bytes(4, endianess)) # BLR X17
		emu.__uc.mem_write(0x10004, 0xd503201f.to_bytes(4, endianess)) 				 # NOP

	function_data = decompilerapi.memory.get_bytes(lowest_addr_aligned, highest_addr_aligned - lowest_addr_aligned)
	emu.__uc.mem_write(raw2virtual(lowest_addr_aligned), function_data)
	

def emulate_range(
		start: int, end: int,
		timeout: int=0, count: int=0,
		should_init_frame: bool=True,
		pre_emulation_routine: Optional[Callable] = None,
		post_emulation_routine: Optional[Callable] = None,
		) -> None:
	"""
	Emulate chosen range of memory. Range end boundary is excluded - [start:end).

	Parameters
	----------
	start: int
		Starting address (address in decompiler, it may change if binary is PIE) of range
	end: int
		Final address (address in decompiler, it may change if binary is PIE) of range
	count: int, optional
		Total number of instructions to emulate (default is None)
	should_init_frame: bool, optional
		Should engine initialize stack frame for chosen range or not. (default True)
	pre_emulation_routine: function, optional
		Function that is called before the emulation starts.
	post_emulation_routine: function, optional
		Function that is called after the emulation ends.
	
	"""
	
	engine = native_emulation_engine()

	if should_init_frame:
		engine.setup_stackframe(start)

	engine.set_pre_emulation_routine(pre_emulation_routine)
	engine.set_post_emulation_routine(post_emulation_routine)
	engine.emulate_range(start, end, timeout, count)

	return engine


def emulate_until_return(
		address: int,
		timeout: int=0, count: int=0):
	pass

endianess2uc = {
	"little": unicorn.unicorn_const.UC_MODE_LITTLE_ENDIAN,
	"big": unicorn.unicorn_const.UC_MODE_BIG_ENDIAN
}

def setup2ucarch(arch, bitness) -> int:
	if arch == decompilerapi.cpu.ARM_ARCH:
		if bitness == 32:
			return unicorn.unicorn_const.UC_ARCH_ARM
		elif bitness == 64:
			return unicorn.unicorn_const.UC_ARCH_ARM64
		else:
			raise NotImplementedError("TODO: somehow handle 16-bit arm")
	else:
		raise NotImplementedError("Currently only arm supported")


def native_emulation_engine():
	arch = decompilerapi.get_arch()

	if arch != 'arm':
		raise NotImplementedError("Any other archs than ARM not yet supported")

	return Aarch64EmulationEngine()

class BaseEmulationEngine:
	_regs = None

	def __init__(self, arch: int, options: int, strict: bool = False):
		options|= endianess2uc[decompilerapi.get_endianess()]
		
		self._logger = logger.Logger("Emu")
		self.uc = unicorn.Uc(arch, options)
		self.mem = memory.MemoryManager(self.uc, decompilerapi.get_endianess())
		self.regs = memory.Registers(self._regs)
		self.strict = strict
		self.user_data = {"self": self}
		self.__pre_emulation_routine = None
		self.__post_emulation_routine = None

	def add_hook(self, hook_type, hook_handler):
		raise NotImplementedError
	
	def emulate_range(self, start: int, end: int, timeout:int=0, count: int=0):
		self.run_pre_emulation_routine()

		self._logger.info("Emulating range raw(%#x - %#x), virtual(%#x - %#x)" % (
				start,
				end,
				memory.raw2virtual(start),
				memory.raw2virtual(end)
			)
		)

		start = memory.raw2virtual(start)
		end = memory.raw2virtual(end)

		self.uc.emu_start(start, end, timeout, count)

		self.run_post_emulation_routine()

	def run_pre_emulation_routine(self) -> None:
		if self.__pre_emulation_routine is not None:
			self.__pre_emulation_routine(self)

	def run_post_emulation_routine(self) -> None:
		if self.__post_emulation_routine is not None:
			self.__post_emulation_routine(self)
	
	def set_pre_emulation_routine(self, routine: Optional[Callable]) -> None:
		self.__pre_emulation_routine = routine

	def set_post_emulation_routine(self, routine: Optional[Callable]) -> None:
		self.__post_emulation_routine = routine

	def setup_stackframe(self, address: int=None, frame_size=const.FRAME_SIZE):
		raise NotImplementedError
	
	def skip_instruction(self):
		raise NotImplementedError

	def reset_memory(self):
		for region in self.uc.mem_regions():
			self.uc.mem_unmap(region[0], region[1] - region[0] + 1)


class Aarch64EmulationEngine(BaseEmulationEngine):
	_regs = {
		"R0": unicorn.arm64_const.UC_ARM64_REG_X0, "R1": unicorn.arm64_const.UC_ARM64_REG_X1,
		"R2": unicorn.arm64_const.UC_ARM64_REG_X2, "R3": unicorn.arm64_const.UC_ARM64_REG_X3,
		"R4": unicorn.arm64_const.UC_ARM64_REG_X4, "R5": unicorn.arm64_const.UC_ARM64_REG_X5,
		"R6": unicorn.arm64_const.UC_ARM64_REG_X6, "R7": unicorn.arm64_const.UC_ARM64_REG_X7,
		"R8": unicorn.arm64_const.UC_ARM64_REG_X8, "R9": unicorn.arm64_const.UC_ARM64_REG_X9,
		"R10": unicorn.arm64_const.UC_ARM64_REG_X10, "R11": unicorn.arm64_const.UC_ARM64_REG_X11,
		"R12": unicorn.arm64_const.UC_ARM64_REG_X12, "R13": unicorn.arm64_const.UC_ARM64_REG_X13,
		"R14": unicorn.arm64_const.UC_ARM64_REG_X14, "R15": unicorn.arm64_const.UC_ARM64_REG_X15,
		"X0": unicorn.arm64_const.UC_ARM64_REG_X0, "X1": unicorn.arm64_const.UC_ARM64_REG_X1,
		"X2": unicorn.arm64_const.UC_ARM64_REG_X2, "X3": unicorn.arm64_const.UC_ARM64_REG_X3,
		"X4": unicorn.arm64_const.UC_ARM64_REG_X4, "X5": unicorn.arm64_const.UC_ARM64_REG_X5,
		"X6": unicorn.arm64_const.UC_ARM64_REG_X6, "X7": unicorn.arm64_const.UC_ARM64_REG_X7,
		"X8": unicorn.arm64_const.UC_ARM64_REG_X8, "X9": unicorn.arm64_const.UC_ARM64_REG_X9,
		"X10": unicorn.arm64_const.UC_ARM64_REG_X10, "X11": unicorn.arm64_const.UC_ARM64_REG_X11,
		"X12": unicorn.arm64_const.UC_ARM64_REG_X12, "X13": unicorn.arm64_const.UC_ARM64_REG_X13,
		"X14": unicorn.arm64_const.UC_ARM64_REG_X14, "X15": unicorn.arm64_const.UC_ARM64_REG_X15,
		"X16": unicorn.arm64_const.UC_ARM64_REG_X16, "X17": unicorn.arm64_const.UC_ARM64_REG_X17,
		"X18": unicorn.arm64_const.UC_ARM64_REG_X18, "X19": unicorn.arm64_const.UC_ARM64_REG_X19,
		"X20": unicorn.arm64_const.UC_ARM64_REG_X20, "X21": unicorn.arm64_const.UC_ARM64_REG_X21,
		"X22": unicorn.arm64_const.UC_ARM64_REG_X22, "X23": unicorn.arm64_const.UC_ARM64_REG_X23,
		"X24": unicorn.arm64_const.UC_ARM64_REG_X24, "X25": unicorn.arm64_const.UC_ARM64_REG_X25,
		"X26": unicorn.arm64_const.UC_ARM64_REG_X26, "X27": unicorn.arm64_const.UC_ARM64_REG_X27,
		"X28": unicorn.arm64_const.UC_ARM64_REG_X28, "X29": unicorn.arm64_const.UC_ARM64_REG_X29,
		"X30": unicorn.arm64_const.UC_ARM64_REG_X30, "W0": unicorn.arm64_const.UC_ARM64_REG_W0,
		"W1": unicorn.arm64_const.UC_ARM64_REG_W1, "W2": unicorn.arm64_const.UC_ARM64_REG_W2,
		"W3": unicorn.arm64_const.UC_ARM64_REG_W3, "W4": unicorn.arm64_const.UC_ARM64_REG_W4,
		"W5": unicorn.arm64_const.UC_ARM64_REG_W5, "W6": unicorn.arm64_const.UC_ARM64_REG_W6,
		"W7": unicorn.arm64_const.UC_ARM64_REG_W7, "W8": unicorn.arm64_const.UC_ARM64_REG_W8,
		"W9": unicorn.arm64_const.UC_ARM64_REG_W9, "W10": unicorn.arm64_const.UC_ARM64_REG_W10,
		"W11": unicorn.arm64_const.UC_ARM64_REG_W11, "W12": unicorn.arm64_const.UC_ARM64_REG_W12,
		"W13": unicorn.arm64_const.UC_ARM64_REG_W13, "W14": unicorn.arm64_const.UC_ARM64_REG_W14,
		"W15": unicorn.arm64_const.UC_ARM64_REG_W15, "W16": unicorn.arm64_const.UC_ARM64_REG_W16,
		"W17": unicorn.arm64_const.UC_ARM64_REG_W17, "W18": unicorn.arm64_const.UC_ARM64_REG_W18,
		"W19": unicorn.arm64_const.UC_ARM64_REG_W19, "W20": unicorn.arm64_const.UC_ARM64_REG_W20,
		"W21": unicorn.arm64_const.UC_ARM64_REG_W21, "W22": unicorn.arm64_const.UC_ARM64_REG_W22,
		"W23": unicorn.arm64_const.UC_ARM64_REG_W23, "W24": unicorn.arm64_const.UC_ARM64_REG_W24,
		"W25": unicorn.arm64_const.UC_ARM64_REG_W25, "W26": unicorn.arm64_const.UC_ARM64_REG_W26,
		"W27": unicorn.arm64_const.UC_ARM64_REG_W7, "W28": unicorn.arm64_const.UC_ARM64_REG_W28,
		"W29": unicorn.arm64_const.UC_ARM64_REG_W29, "W30": unicorn.arm64_const.UC_ARM64_REG_W30,
		"PC": unicorn.arm64_const.UC_ARM64_REG_PC, "pc": unicorn.arm64_const.UC_ARM64_REG_PC,
		"LR": unicorn.arm64_const.UC_ARM64_REG_X30, "SP": unicorn.arm64_const.UC_ARM64_REG_SP,
		"sp": unicorn.arm64_const.UC_ARM64_REG_SP, "FP": unicorn.arm64_const.UC_ARM64_REG_FP,
		"fp": unicorn.arm64_const.UC_ARM64_REG_FP,
		"S0": unicorn.arm64_const.UC_ARM64_REG_S0, "S1": unicorn.arm64_const.UC_ARM64_REG_S1,
		"S2": unicorn.arm64_const.UC_ARM64_REG_S2, "S3": unicorn.arm64_const.UC_ARM64_REG_S3,
		"S4": unicorn.arm64_const.UC_ARM64_REG_S4, "S5": unicorn.arm64_const.UC_ARM64_REG_S5,
		"S6": unicorn.arm64_const.UC_ARM64_REG_S6, "S7": unicorn.arm64_const.UC_ARM64_REG_S7,
		"S8": unicorn.arm64_const.UC_ARM64_REG_S8, "S9": unicorn.arm64_const.UC_ARM64_REG_S9,
		"S10": unicorn.arm64_const.UC_ARM64_REG_S10, "S11": unicorn.arm64_const.UC_ARM64_REG_S11,
		"S12": unicorn.arm64_const.UC_ARM64_REG_S12, "S13": unicorn.arm64_const.UC_ARM64_REG_S13,
		"S14": unicorn.arm64_const.UC_ARM64_REG_S14, "S15": unicorn.arm64_const.UC_ARM64_REG_S15,
		"S16": unicorn.arm64_const.UC_ARM64_REG_S16, "S17": unicorn.arm64_const.UC_ARM64_REG_S17,
		"S18": unicorn.arm64_const.UC_ARM64_REG_S18, "S19": unicorn.arm64_const.UC_ARM64_REG_S19,
		"S20": unicorn.arm64_const.UC_ARM64_REG_S20, "S21": unicorn.arm64_const.UC_ARM64_REG_S21,
		"S22": unicorn.arm64_const.UC_ARM64_REG_S22, "S23": unicorn.arm64_const.UC_ARM64_REG_S23,
		"S24": unicorn.arm64_const.UC_ARM64_REG_S24, "S25": unicorn.arm64_const.UC_ARM64_REG_S25,
		"S26": unicorn.arm64_const.UC_ARM64_REG_S26, "S27": unicorn.arm64_const.UC_ARM64_REG_S27,
		"S28": unicorn.arm64_const.UC_ARM64_REG_S28, "S29": unicorn.arm64_const.UC_ARM64_REG_S29,
		"S30": unicorn.arm64_const.UC_ARM64_REG_S30, "S31": unicorn.arm64_const.UC_ARM64_REG_S31,
		"D0": unicorn.arm64_const.UC_ARM64_REG_D0, "D1": unicorn.arm64_const.UC_ARM64_REG_D1,
		"D2": unicorn.arm64_const.UC_ARM64_REG_D2, "D3": unicorn.arm64_const.UC_ARM64_REG_D3,
		"D4": unicorn.arm64_const.UC_ARM64_REG_D4, "D5": unicorn.arm64_const.UC_ARM64_REG_D5,
		"D6": unicorn.arm64_const.UC_ARM64_REG_D6, "D7": unicorn.arm64_const.UC_ARM64_REG_D7,
		"D8": unicorn.arm64_const.UC_ARM64_REG_D8, "D9": unicorn.arm64_const.UC_ARM64_REG_D9,
		"D10": unicorn.arm64_const.UC_ARM64_REG_D10, "D11": unicorn.arm64_const.UC_ARM64_REG_D11,
		"D12": unicorn.arm64_const.UC_ARM64_REG_D12, "D13": unicorn.arm64_const.UC_ARM64_REG_D13,
		"D14": unicorn.arm64_const.UC_ARM64_REG_D14, "D15": unicorn.arm64_const.UC_ARM64_REG_D15,
		"D16": unicorn.arm64_const.UC_ARM64_REG_D16, "D17": unicorn.arm64_const.UC_ARM64_REG_D17,
		"D18": unicorn.arm64_const.UC_ARM64_REG_D18, "D19": unicorn.arm64_const.UC_ARM64_REG_D19,
		"D20": unicorn.arm64_const.UC_ARM64_REG_D20, "D21": unicorn.arm64_const.UC_ARM64_REG_D21,
		"D22": unicorn.arm64_const.UC_ARM64_REG_D22, "D23": unicorn.arm64_const.UC_ARM64_REG_D23,
		"D24": unicorn.arm64_const.UC_ARM64_REG_D24, "D25": unicorn.arm64_const.UC_ARM64_REG_D25,
		"D26": unicorn.arm64_const.UC_ARM64_REG_D26, "D27": unicorn.arm64_const.UC_ARM64_REG_D27,
		"D28": unicorn.arm64_const.UC_ARM64_REG_D28, "D29": unicorn.arm64_const.UC_ARM64_REG_D29,
		"D30": unicorn.arm64_const.UC_ARM64_REG_D30, "D31": unicorn.arm64_const.UC_ARM64_REG_D31,
		"H0": unicorn.arm64_const.UC_ARM64_REG_H0, "H1": unicorn.arm64_const.UC_ARM64_REG_H1,
		"H2": unicorn.arm64_const.UC_ARM64_REG_H2, "H3": unicorn.arm64_const.UC_ARM64_REG_H3,
		"H4": unicorn.arm64_const.UC_ARM64_REG_H4, "H5": unicorn.arm64_const.UC_ARM64_REG_H5,
		"H6": unicorn.arm64_const.UC_ARM64_REG_H6, "H7": unicorn.arm64_const.UC_ARM64_REG_H7,
		"H8": unicorn.arm64_const.UC_ARM64_REG_H8, "H9": unicorn.arm64_const.UC_ARM64_REG_H9,
		"H10": unicorn.arm64_const.UC_ARM64_REG_H10, "H11": unicorn.arm64_const.UC_ARM64_REG_H11,
		"H12": unicorn.arm64_const.UC_ARM64_REG_H12, "H13": unicorn.arm64_const.UC_ARM64_REG_H13,
		"H14": unicorn.arm64_const.UC_ARM64_REG_H14, "H15": unicorn.arm64_const.UC_ARM64_REG_H15,
		"H16": unicorn.arm64_const.UC_ARM64_REG_H16, "H17": unicorn.arm64_const.UC_ARM64_REG_H17,
		"H18": unicorn.arm64_const.UC_ARM64_REG_H18, "H19": unicorn.arm64_const.UC_ARM64_REG_H19,
		"H20": unicorn.arm64_const.UC_ARM64_REG_H20, "H21": unicorn.arm64_const.UC_ARM64_REG_H21,
		"H22": unicorn.arm64_const.UC_ARM64_REG_H22, "H23": unicorn.arm64_const.UC_ARM64_REG_H23,
		"H24": unicorn.arm64_const.UC_ARM64_REG_H24, "H25": unicorn.arm64_const.UC_ARM64_REG_H25,
		"H26": unicorn.arm64_const.UC_ARM64_REG_H26, "H27": unicorn.arm64_const.UC_ARM64_REG_H27,
		"H28": unicorn.arm64_const.UC_ARM64_REG_H28, "H29": unicorn.arm64_const.UC_ARM64_REG_H29,
		"H30": unicorn.arm64_const.UC_ARM64_REG_H30, "H31": unicorn.arm64_const.UC_ARM64_REG_H31,
		"Q0": unicorn.arm64_const.UC_ARM64_REG_Q0, "Q1": unicorn.arm64_const.UC_ARM64_REG_Q1,
		"Q2": unicorn.arm64_const.UC_ARM64_REG_Q2, "Q3": unicorn.arm64_const.UC_ARM64_REG_Q3,
		"Q4": unicorn.arm64_const.UC_ARM64_REG_Q4, "Q5": unicorn.arm64_const.UC_ARM64_REG_Q5,
		"Q6": unicorn.arm64_const.UC_ARM64_REG_Q6, "Q7": unicorn.arm64_const.UC_ARM64_REG_Q7,
		"Q8": unicorn.arm64_const.UC_ARM64_REG_Q8, "Q9": unicorn.arm64_const.UC_ARM64_REG_Q9,
		"Q10": unicorn.arm64_const.UC_ARM64_REG_Q10, "Q11": unicorn.arm64_const.UC_ARM64_REG_Q11,
		"Q12": unicorn.arm64_const.UC_ARM64_REG_Q12, "Q13": unicorn.arm64_const.UC_ARM64_REG_Q13,
		"Q14": unicorn.arm64_const.UC_ARM64_REG_Q14, "Q15": unicorn.arm64_const.UC_ARM64_REG_Q15,
		"Q16": unicorn.arm64_const.UC_ARM64_REG_Q16, "Q17": unicorn.arm64_const.UC_ARM64_REG_Q17,
		"Q18": unicorn.arm64_const.UC_ARM64_REG_Q18, "Q19": unicorn.arm64_const.UC_ARM64_REG_Q19,
		"Q20": unicorn.arm64_const.UC_ARM64_REG_Q20, "Q21": unicorn.arm64_const.UC_ARM64_REG_Q21,
		"Q22": unicorn.arm64_const.UC_ARM64_REG_Q22, "Q23": unicorn.arm64_const.UC_ARM64_REG_Q23,
		"Q24": unicorn.arm64_const.UC_ARM64_REG_Q24, "Q25": unicorn.arm64_const.UC_ARM64_REG_Q25,
		"Q26": unicorn.arm64_const.UC_ARM64_REG_Q26, "Q27": unicorn.arm64_const.UC_ARM64_REG_Q27,
		"Q28": unicorn.arm64_const.UC_ARM64_REG_Q28, "Q29": unicorn.arm64_const.UC_ARM64_REG_Q29,
		"Q30": unicorn.arm64_const.UC_ARM64_REG_Q30, "Q31": unicorn.arm64_const.UC_ARM64_REG_Q31,
		"V0":unicorn.arm64_const.UC_ARM64_REG_V0, "V1":unicorn.arm64_const.UC_ARM64_REG_V1,
		"V2":unicorn.arm64_const.UC_ARM64_REG_V2, "V3":unicorn.arm64_const.UC_ARM64_REG_V3,
		"V4":unicorn.arm64_const.UC_ARM64_REG_V4, "V5":unicorn.arm64_const.UC_ARM64_REG_V5,
		"V6":unicorn.arm64_const.UC_ARM64_REG_V6, "V7":unicorn.arm64_const.UC_ARM64_REG_V7,
		"V8":unicorn.arm64_const.UC_ARM64_REG_V8, "V9":unicorn.arm64_const.UC_ARM64_REG_V9,
		"V10":unicorn.arm64_const.UC_ARM64_REG_V10, "V11":unicorn.arm64_const.UC_ARM64_REG_V11,
		"V12":unicorn.arm64_const.UC_ARM64_REG_V12, "V13":unicorn.arm64_const.UC_ARM64_REG_V13,
		"V14":unicorn.arm64_const.UC_ARM64_REG_V14, "V15":unicorn.arm64_const.UC_ARM64_REG_V15,
		"V16":unicorn.arm64_const.UC_ARM64_REG_V16, "V17":unicorn.arm64_const.UC_ARM64_REG_V17,
		"V18":unicorn.arm64_const.UC_ARM64_REG_V18, "V19":unicorn.arm64_const.UC_ARM64_REG_V19,
		"V20":unicorn.arm64_const.UC_ARM64_REG_V20, "V21":unicorn.arm64_const.UC_ARM64_REG_V21,
		"V22":unicorn.arm64_const.UC_ARM64_REG_V22, "V23":unicorn.arm64_const.UC_ARM64_REG_V23,
		"V24":unicorn.arm64_const.UC_ARM64_REG_V24, "V25":unicorn.arm64_const.UC_ARM64_REG_V25,
		"V26":unicorn.arm64_const.UC_ARM64_REG_V26, "V27":unicorn.arm64_const.UC_ARM64_REG_V27,
		"V28":unicorn.arm64_const.UC_ARM64_REG_V28, "V29":unicorn.arm64_const.UC_ARM64_REG_V29,
		"V30":unicorn.arm64_const.UC_ARM64_REG_V30, "V31":unicorn.arm64_const.UC_ARM64_REG_V31,
		"ret": unicorn.arm64_const.UC_ARM64_REG_X0, "link": unicorn.arm64_const.UC_ARM64_REG_X30,
	}

	def __init__(self, *args, **kwargs):		
		options = unicorn.UC_MODE_ARM
		super().__init__(unicorn.UC_ARCH_ARM64, options, *args, **kwargs)
		# self.hooks = defaultdict(list)

		self.uc.hook_add(unicorn.UC_HOOK_MEM_READ_UNMAPPED | unicorn.UC_HOOK_MEM_WRITE_UNMAPPED |
                         unicorn.UC_HOOK_MEM_FETCH_UNMAPPED, memory.handle_memory_fault, self.user_data)
		
		self.uc.hook_add(unicorn.UC_HOOK_CODE, code_hook, self.user_data)

	def setup_stackframe(self, address=None, frame_size: int=const.FRAME_SIZE):
		self.uc.mem_map(const.STACK_BASE - 4 * 0x1000, 8 * 0x1000)
		self.uc.reg_write(self.regs.sp, const.STACK_BASE)

		if address is not None:
			frame_size = decompilerapi.get_func_frame_size(address)

		sp_value = self.uc.reg_read(self.regs.sp)
		self.uc.mem_write(sp_value, util.p64(0xDEADBEEFCAFEBABE))
		self.uc.mem_write(sp_value - 4, util.p64(0xDEADBEEFCAFEBABE))
		self.uc.reg_write(self.regs.fp, sp_value - 8)
		self.uc.reg_write(self.regs.fp, sp_value - frame_size)

def code_hook(uc, address, size, user_data) -> bool:
	print("[*] Code hook: %#x -> %#x" % (address, user_data["self"].mem.read_dword(address)))
	if user_data["self"].mem.read_dword(address) == 0xd65f03c0:
		uc.emu_stop()