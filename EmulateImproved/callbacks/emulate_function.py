import binaryninja
from binaryninja.enums import VariableSourceType

from .bnplugintools import PyToolsPluginCommand, get_action_manager

from werewolf import emu
from werewolf.fileview.binaryninja import BinaryNinjaFileView
from werewolf.formalargument import ImmediateArgument, RegisterStorage, StackStorage
from werewolf.differ import MemoryDiffer


class EmulateFunction(PyToolsPluginCommand):
	display_name = "Emulate function"
	description = "Emulate certain function"

	def __init__(self):
		pass

	def activate(cls, bv, func: binaryninja.Function):
		# engine = emu.run_emulate_function(BinaryNinjaFileView(bv), func.start)
		raise NotImplementedError

	def is_valid(cls, bv, func):
		return True


get_action_manager().register(EmulateFunction())
