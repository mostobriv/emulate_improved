import idaapi


class HexRaysCallbackManager(object):
	def __init__(self):
		self.__hexrays_hooks = list()

	def initialize(self) -> None:
		pass

	def finalize(self) -> None:
		for h in self.__hexrays_hooks:
			h.unhook()

	def register(self, hx_hook, quite=True) -> None:
		self.__hexrays_hooks.append(hx_hook)
		res = hx_hook.hook()
		if not quite:
			# TODO: add name attribute to HexRaysEventHook to make pretty print.
			print("[*] Registered %s hexrays-hook with status %d" % (hx_hook, res))


hx_callback_manager = HexRaysCallbackManager()

class HexRaysEventHook(idaapi.Hexrays_Hooks):
	def __init__(self):
		super().__init__()
