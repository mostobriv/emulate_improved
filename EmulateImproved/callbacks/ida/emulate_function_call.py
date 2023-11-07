import idaapi

from . import actions
from EmulateImproved.core import emu

class EmulateFunctionCall(actions.HexRaysPopupAction):
	description = "Emulate this function call"

	def __init__(self):
		super().__init__()


	def activate(self, ctx):
		print(type(ctx))
		vdui = idaapi.get_widget_vdui(ctx.widget)
		widget_type = ctx.widget_type

		pointed_item = vdui.item.it.to_specific_type
		parent_item = vdui.cfunc.body.find_parent_of(pointed_item).to_specific_type

		if pointed_item.op == idaapi.cot_call:
			call_expr = pointed_item
		else:
			call_expr = parent_item

		called_function_address = call_expr.x.obj_ea
		called_function_args = extract_arguments(call_expr)

		emu.emulate_function(called_function_address)

	def check(self, vdui: idaapi.vdui_t) -> bool:
		if vdui.item.citype != idaapi.VDI_EXPR:
			return False
		
		pointed_item = vdui.item.it.to_specific_type
		parent_expr = vdui.cfunc.body.find_parent_of(pointed_item).to_specific_type

		if parent_expr.op != idaapi.cot_call and pointed_item.op != idaapi.cot_call:
			return False

		return True


def extract_arguments(call_expr: idaapi.cexpr_t) -> list:
	# TODO: implement
	return []

actions.action_manager.register(EmulateFunctionCall())