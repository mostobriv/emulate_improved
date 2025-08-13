import binaryninja
from binaryninja import HighLevelILOperation, VariableSourceType
from binaryninjaui import LinearView  # type: ignore

from .bnplugintools import PyToolsUIAction, get_action_manager


from werewolf.bnscriptingprovider import run_emulate_hlil_call, run_emulate_mlil_call
from werewolf.emulengine.base import EmulationEngine
# from werewolf.differ import MemoryDiffer

from ..core import utils


# Handling 3 cases:
# - when call instruction is directly provided (HLIL_CALL)
# - when func pointer instruction is provided (user clicked on the function name in HLIL) (HLIL_CONST_PTR)
# - TODO: when user clicked on whole line (HLIL_???)
def handle_hlil_call(
	instr: binaryninja.HighLevelILInstruction, bv: binaryninja.BinaryView
) -> EmulationEngine:
	if instr.operation == HighLevelILOperation.HLIL_CALL:
		return run_emulate_hlil_call(instr, bv)

	elif instr.operation == HighLevelILOperation.HLIL_CONST_PTR:
		assert instr.parent.operation == HighLevelILOperation.HLIL_CALL
		return run_emulate_hlil_call(instr.parent, bv)

	else:
		raise ValueError(f"Invalid HLIL instruction provided: {instr!r}")


class EmulateFunctionCall(PyToolsUIAction):
	display_name = "Emulate concrete function call"
	description = "Try extract arguments and emulate concrete function call"

	def __init__(self):
		super().__init__()

	def activate(self, context):
		if context is None:
			return

		if not isinstance(context.widget, LinearView):
			return

		token_state = context.token

		if not token_state.focused:
			return

		il_function = None
		if (
			view_type := utils.get_il_view_type(context.context)
		) == binaryninja.FunctionGraphType.HighLevelILFunctionGraph:
			il_function = context.highLevelILFunction
			handler = handle_hlil_call
		elif view_type == binaryninja.FunctionGraphType.MediumLevelILFunctionGraph:
			il_function = context.mediumLevelILFunction
			raise NotImplementedError
		else:
			self.logger.log_warn(f"Unsupported il view type: {view_type!r}")
			return

		instruction = None
		if token_state.token.il_expr_index != 0xFFFFFFFFFFFFFFFF:
			instruction = il_function.get_expr(token_state.token.il_expr_index)
		else:
			instruction = il_function[context.instrIndex]

		handler(instruction, context.binaryView)

	def is_valid(self, context):
		return True


get_action_manager().register(EmulateFunctionCall())
