import idaapi

def get_selected_range(vu: idaapi.vdui_t = None) -> tuple:
	if vu is None:
		widget = idaapi.get_current_widget()
		vu = idaapi.get_widget_vdui(widget)