# Attempts to more aggressively demangle any Microsoft-style mangled symbols.
# DemanglerCmd is not used as it will filter by program format (e.g. Microsoft
# Demangler will not be used if the executable format is not PE/COFF). Instead,
# this script invokes the MicrosoftDemangler directly on any symbol prefixed by
# `?`. Additionally, this script handles `@name@X` (fastcall) and `_name@X`
# (stdcall) mangles.
# @author: Matt Borgerson
# @category: Symbol
# from loguru import logger
from ghidra.app.util.demangler import DemanglerOptions
from ghidra.app.util.demangler.microsoft import MicrosoftDemangler
from ghidra.program.model.symbol import SourceType
import re

st = currentProgram().getSymbolTable()
n = currentProgram().getNamespaceManager().getGlobalNamespace()

numDemangled = 0
failures = []
# logger.info('[dmore] ')
for s in st.getSymbols(n):
	name = s.getName()
	addr = s.getAddress()

	if name.startswith('?'):
		# Attempt using Microsoft demangler
		try:
			demangled = MicrosoftDemangler().demangle(name, True)
			# logger.info(f'[msDemangler] {name} to {demangled}')
			s.delete()
			demangled.applyTo(currentProgram(), addr, DemanglerOptions(), monitor())
			numDemangled += 1
		except Exception as e:
			# logger.debug(f'[msDemangler] failed {e} {type(e)} name:{name}')
			failures.append(name)

	elif name.startswith('@') or name.startswith('_'):
		# Attempt decoding @func@0 (__fastcall) and _func@0 (__stdcall) style mangle
		# https://en.wikipedia.org/wiki/Name_mangling#Standardised_name_mangling_in_C++
		isFastcall, isStdcall = False, False
		realName, bytesInParams = None, 0
		f = None
		m = re.match('^@(\w+)@([0-9]+)$', name)
		if m is not None:
			isFastcall = True
			realName, bytesInParams = m.groups()
		else:
			m = re.match('^_(\w+)@([0-9]+)$', name)
			if m is not None:
				isStdcall = True
				realName, bytesInParams = m.groups()

		if isFastcall or isStdcall:
			# logger.debug(f'Demangling: {name}')
			bytesInParams = int(bytesInParams)

			# Get or create the function
			s.delete()
			f = getFunctionAt(addr)
			if f is None:
				f = createFunction(addr, realName)

			if f is None:
				# logger.info(f'[dmore] nofunc {realName}')
				failures.append(name)
			else:
				if realName:
					# logger.info(f'[dmore] name: {realName} to {f} ')
					f.setName(realName, SourceType.ANALYSIS)
					f.setComment(name)
					convention = '__fastcall' if isFastcall else '__stdcall'
					f.setCallingConvention(convention)
					numDemangled += 1
	else:
		continue
	# numDemangled += 1

# logger.debug(f'[dmore] Done names {numDemangled} Failed to demangle {len(failures)}')
if len(failures) > 0:
	for n in sorted(failures):
		print('[fail] ', n)
		# logger.debug(f'[fail] {n}')
