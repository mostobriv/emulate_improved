import binaryninja
import binaryninjaui


def get_il_view_type(
	context: binaryninjaui.UIContext,
) -> binaryninja.FunctionGraphType | None:
	view_location = context.getCurrentViewFrame().getViewLocation()
	if view_location is None:
		return None

	return view_location.getILViewType().view_type
