import binaryninja

from .bnplugintools import PyToolsPluginCommand, get_action_manager

from werewolf import emu
from werewolf.fileview.binaryninja import BinaryNinjaFileView
from werewolf.differ import MemoryDiffer


class EmulateRange(PyToolsPluginCommand):
	display_name = "Emulate range of instructions"
	description = "Emulate range of instructions"
	type = binaryninja.PluginCommandType.RangePluginCommand

	def __init__(self):
		super().__init__()

	def activate(cls, bv, address, length):
		engine = emu.run_emulate_range(BinaryNinjaFileView(bv), address, address + length)

		differ = MemoryDiffer(engine.mem, engine.fv)
		with bv.undoable_transaction():
			differ.apply_changes()

	def is_valid(cls, bv, address, length):
		return bv.is_offset_readable(address) and bv.is_offset_readable(address + length)


get_action_manager().register(EmulateRange())
