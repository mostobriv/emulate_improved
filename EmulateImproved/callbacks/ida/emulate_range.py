import idaapi

from . import actions
from EmulateImproved.core import emu


class EmulateRange(actions.AsmPopupAction):
	description = "Emulate range"

	def __init__(self):
		super().__init__()

	def activate(self, ctx):
		vdui = idaapi.get_widget_vdui(ctx.widget)
		widget_type = ctx.widget_type

		is_range_selected, range_start, range_end = get_range_for_assembly_view(ctx.widget)
		if not is_range_selected:
			print("Currently single instruction emulation not supported")
			return
		

		emu.emulate_range(range_start, range_end)

	def check(self, widget) -> bool:
		widget_type = idaapi.get_widget_type(widget)
		return widget_type == idaapi.BWN_DISASM


def get_range_for_assembly_view(widget):
	return idaapi.read_range_selection(widget)
	
actions.action_manager.register(EmulateRange())