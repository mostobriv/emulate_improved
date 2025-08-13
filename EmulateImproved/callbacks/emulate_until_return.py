import binaryninja

from .bnplugintools import PyToolsPluginCommand, get_action_manager

from werewolf import emu
from werewolf.fileview.binaryninja import BinaryNinjaFileView
from werewolf.differ import MemoryDiffer


class EmulateUntilReturn(PyToolsPluginCommand):
	display_name = "Emulate until return"
	description = "Emulate until return instruction is met"
	type = binaryninja.PluginCommandType.AddressPluginCommand

	def __init__(self):
		super().__init__()

	def activate(cls, bv, addr):
		engine = emu.run_emulate_until_return(BinaryNinjaFileView(bv), addr)

		differ = MemoryDiffer(engine.mem, engine.fv)
		with bv.undoable_transaction():
			differ.apply_changes()

	def is_valid(cls, bv, addr):
		return bv.is_offset_readable(addr)


get_action_manager().register(EmulateUntilReturn())
