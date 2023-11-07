import idaapi

from .callbacks import hx_callback_manager, HexRaysEventHook

class ActionManager(object):
	def __init__(self):
		self.__actions = []
		self.popup_hooks = []

	def register(self, action) -> None:
		self.__actions.append(action)
		status = idaapi.register_action(
				idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
			)
		print("[*] Registered %s action with status %d" % (action.name, status))

		if isinstance(action, AsmPopupAction):
			popup_hook = AsmPopupRequestHook(action)
			popup_hook.hook()

			self.popup_hooks.append(popup_hook)

		if isinstance(action, HexRaysPopupAction):
			hx_callback_manager.register(HexRaysPopupRequestHook(action))

	def initialize(self):
		pass

	def finalize(self):
		for hook in self.popup_hooks:
			hook.unhook()

		for action in self.__actions:
			idaapi.unregister_action(action.name)


action_manager = ActionManager()

class Action(idaapi.action_handler_t):
	"""
	Convenience wrapper with name property allowing to be registered in IDA using ActionManager
	"""
	description = None
	hotkey = None

	def __init__(self):
		super().__init__()

	@property
	def name(self) -> str:
		return "EmulateImproved:" + type(self).__name__

	def activate(self, ctx: idaapi.action_ctx_base_t) -> None:
		raise NotImplementedError

	def update(self, ctx: idaapi.action_ctx_base_t) -> None:
		raise NotImplementedError


class AsmPopupAction(Action):
	"""
	Wrapper around Action. Represents Action which can be added to menu after right-clicking in any window.
	Has `check` method that should tell whether Action should be added to popup menu when different items
	are right-clicked.
	"""
	
	def __init__(self):
		super(AsmPopupAction, self).__init__()

	def activate(self, ctx: idaapi.action_ctx_base_t) -> None:
		raise NotImplementedError

	def check(self, widget) -> bool:
		raise NotImplementedError

	def update(self, ctx: idaapi.action_ctx_base_t) -> int:
		if ctx.widget_type == idaapi.BWN_DISASM:
			return idaapi.AST_ENABLE_FOR_WIDGET
		return idaapi.AST_DISABLE_FOR_WIDGET

class AsmPopupRequestHook(idaapi.UI_Hooks):
	def __init__(self, action):
		super(AsmPopupRequestHook, self).__init__()
		self.__action = action

	def finish_populating_widget_popup(self, widget, popup):
		if self.__action.check(widget):
			print("Attached action %s to popup with result: %#x" % (self.__action.name, idaapi.attach_action_to_popup(widget, popup, self.__action.name, None)))


class HexRaysPopupAction(Action):
	"""
	Wrapper around Action. Represents Action which can be added to menu after right-clicking in Decompile window.
	Has `check` method that should tell whether Action should be added to popup menu when different items
	are right-clicked.
	Children of this class can also be fired by hot-key without right-clicking if one provided in `hotkey`
	static member.
	"""

	def __init__(self):
		super(HexRaysPopupAction, self).__init__()

	def activate(self, ctx: idaapi.action_ctx_base_t) -> None:
		raise NotImplementedError

	def check(self, hx_view: idaapi.vdui_t) -> bool:
		raise NotImplementedError

	def update(self, ctx: idaapi.action_ctx_base_t) -> int:
		if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
			return idaapi.AST_ENABLE_FOR_WIDGET
		return idaapi.AST_DISABLE_FOR_WIDGET


class HexRaysPopupRequestHook(HexRaysEventHook):
	"""
	This is wrapper around HexRaysPopupHook which allows to dynamically decide whether to add Action to popup
	menu or not.
	Register this in CallbackManager.
	"""
	def __init__(self, action):
		super(HexRaysPopupRequestHook, self).__init__()
		self.__action = action

	def populating_popup(self, widget, popup, hx_view):
		if self.__action.check(hx_view):
			idaapi.attach_action_to_popup(widget, popup, self.__action.name, None)
		return 0