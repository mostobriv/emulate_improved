from typing import *



__decompilerapi_initialized = False

try:
	from .ida import *
	__decompilerapi_initialized = True
	print("[*] Initialized IDA Pro decompiler api.")
except Exception as e:
	print("Got exception when importing: %s" % e)

if not __decompilerapi_initialized:
	try:
		from bn import *
		__decompilerapi_initialized = True
		print("[*] Initialized Binary Ninja decompiler api.")
	except Exception as e:
		print("Got exception when importing: %s" % e)

assert __decompilerapi_initialized