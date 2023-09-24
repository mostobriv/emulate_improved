import idaapi

from . import actions
from EmulateImproved import core


class EmulateRange(actions.Action):
	def __init__(self):
		super().__init__()

	def activate(self, ctx):
		vdui = idaapi.get_widget_vdui(ctx.widget)
		widget_type = ctx.widget_type

		range_start, range_end = None, None
		if widget_type == idaapi.BWN_DISASM:
			range_start, range_end = get_range_for_assembly_view(vdui)
		else:
			raise NotImplementedError
		

	def update(self, ctx):
		if ctx.widget_type in [idaapi.BWN_PSEUDOCODE, idaapi.BWN_DISASM]:
			return idaapi.AST_ENABLE_FOR_WIDGET
		return idaapi.AST_DISABLE_FOR_WIDGET


def get_range_for_assembly_view(vdui):
	return core.ui.get_selected_range(vdui)

actions.action_manager.register(EmulateRange())