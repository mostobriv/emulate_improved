import unicorn

class EmulationEngine:
	def __init__(self, *opt):
		self.__engine = unicorn.Uc(*opt)



class HookManager:
	def __init__(self):
		pass