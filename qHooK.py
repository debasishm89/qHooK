'''
qHooK v0.1
Author : Debasish Mandal
Blog :http://www.debasish.in/
Twitter : https://twitter.com/debasishm89
 
qHooK is a very simple python script (dependent on pydbg) 
which hooks user defined Win32 APIs in any process and prepare a CSV 
report with various interesting information which can  help reverse 
engineer to track down / analyse unknown exploit samples / shellcode.

'''
from pydbg import *
from pydbg.defines import *
from struct import unpack
import pydasm
import csv
import datetime
from random import randint


#####################################################  Config   ####################################
'''
It was noticed that, if we try to de-reference and read large amount of data from memory , target application may crash or hang.
So we are using "white_list" dictionary. Here we can define important API arguments,for which you want more to be data to be read/logged.
For example,in case of a call to CreateFileA you may want to see full path of filename from 2nd argument, so it will read 30 or 40 bytes depending on definition.
By default this script will only de-reference and read/log only 4 bytes. You should definitely refer to MSDN while adding more element in this dictionary
'''
white_list = {'kernel32.dll!GetProcAddress':[2,25], 	# Read 25 bytes for 2nd argument of GetProcAddress
			  'kernel32.dll!CreateFileW':[1,50], 		# Read 50 bytes for 1st argument of CreateFileW
			  'kernel32.dll!CreateFileA':[1,50],		# Read 50 bytes for 1st argument of CreateFileA
			  'kernel32.dll!WriteFile':[2,50],			# Read 50 bytes for 1st argument of WriteFile
			  'kernel32.dll!WriteFileGather':[2,50],	# Read 50 bytes for 1st argument of WriteFileGather
			  'kernel32.dll!LoadLibraryW':[1,20],		# Read 20 bytes for 1st argument of LoadLibraryW
			  'kernel32.dll!LoadLibraryA':[1,20],		# Read 20 bytes for 1st argument of LoadLibraryA
			  'kernel32.dll!LoadLibraryExA':[1,20],		# Read 20 bytes for 1st argument of LoadLibraryExA
			  'kernel32.dll!LoadLibraryExW':[1,20]}		# Read 20 bytes for 1st argument of LoadLibraryExW
# List of interesting APIS to be Hooked and monitored 
target_apis = {'kernel32.dll!LoadLibraryA':1,
				'kernel32.dll!LoadLibraryExA':1,
				'kernel32.dll!LoadLibraryExW':1,
				'kernel32.dll!LoadLibraryW':1,
				'kernel32.dll!LoadModule':2,
				'kernel32.dll!GetProcAddress':2,
				'kernel32.dll!VirtualProtect':4,
				'kernel32.dll!VirtualProtectEx':4,
				'kernel32.dll!WriteProcessMemory':5,
				'kernel32.dll!WriteFile':5,
				'kernel32.dll!WriteFileEx':5,
				'kernel32.dll!WinExec':2,
				'kernel32.dll!CreateFileA':7,
				'kernel32.dll!WriteFileGather':5}
################################################ Config End #########################################
def openLog():
	f = open("call_log.csv", "wb")
	c = csv.writer(f)
	c.writerow(["Call ID","Time Stamp","API Arguments","API Name","Return Address(Poi to Stack/Heap)","Stack Value(Poi to Stack/Heap)", "If printable Strings", "Disassembly"   , "Raw Hex Bytes"])
def addToLog(data):
	f = open("call_log.csv", "ab")
	c = csv.writer(f)
	c.writerow(data)
def getregion(dbg,address):
	deref_info = dbg.smart_dereference(address,print_dots=False)
	if "(stack)" in deref_info:
		result = "stack"
	elif "(heap)" in deref_info:
		result = "heap"
	else:
		result = "N/A"
	return result
def getDisasm(raw_bin):
	asm_buff = ""
	offset = 0
	while offset < len(raw_bin):
		try:
			i = pydasm.get_instruction(raw_bin[offset:], pydasm.MODE_32)
			instruction = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, 0)
			asm_buff += instruction + '; '
			offset += i.length
		except Exception,e:
			asm_buff += 'Unknown' + ';'
	return asm_buff
def AccessViolationHandler (dbg):
	print '[+] Application Crashed Unexpectedly :( '
	return DBG_CONTINUE
def get_printable (data,data_format):
	discovered = ""
	if data_format == 'hex':
		discovered = data.encode(data_format)
	if data_format == 'printable':
		for char in data:
			if ord(char) > 31 and ord(char) < 126:
				discovered += char
			else:
				discovered += '.'
	if data_format == 'disasm':
		discovered = getDisasm(data)
	return discovered
def sniffAPI(dbg):
	eip = dbg.context.Eip
	esp =  dbg.context.Esp
	ret_addr = hex(unpack('<L',dbg.read_process_memory( dbg.context.Esp , 4 ))[0])
	t1 =  '[+] Call to ' + addr_directory[eip] + '( Ret Addr: ' + ret_addr + '(' + getregion(dbg,int(ret_addr,16))  +')' +' no of Args '+ str ( target_apis[addr_directory[eip]] ) + ')'
	print t1
	offset = 4
	call_id = str(randint(10000000,99999999))
	for arguments in range(0,target_apis[addr_directory[eip]]):
		temp = []
		stack_cont = hex(unpack('<L',dbg.read_process_memory( dbg.context.Esp + offset, 4 ))[0])
		try:
			if addr_directory[eip] in white_list and arguments == white_list[addr_directory[eip]][0]-1:
				#We will read few extra bytes if interesting function occurs (
				d = dbg.read_process_memory( int (stack_cont,16), white_list[addr_directory[eip]][1] )
			else:
				d = dbg.read_process_memory( int (stack_cont,16), 4 )# Read only 4 bytes
			s_h = getregion(dbg,int(stack_cont,16))
		except Exception,e:
			d = 'N/A(Exception)'
			s_h = 'N/A(Exception)'
		temp.append(call_id)																# Unique Random Call ID (Helps little bit to add excel filter)
		temp.append(datetime.datetime.time(datetime.datetime.now()))						# Time Stamp
		temp.append('Argument : ' + str(arguments))											# Argumenr Number
		temp.append(addr_directory[eip])													# API_NAME
		temp.append(ret_addr + '(' + getregion(dbg,int(ret_addr,16))  +')' )				# Return Address
		temp.append(stack_cont + '(' + s_h +')')											# Stack Cont
		temp.append(get_printable(d,'printable'))											# Arg Printable
		temp.append(get_printable(d,'disasm'))												# Arg Disasm
		temp.append(get_printable(d,'hex'))													# Arg Hex Bytes
		addToLog(temp)
		offset += 4
	addToLog(['','','','__','','','','',''])
	return DBG_CONTINUE

def main():
	global addr_directory
	addr_directory = {}
	print '[+] Welcome'
	print '[+] Choose Your option'
	print '[+] 1. Attach to target process (Process Name Required)'
	print '[+] 2. Attach to target process (PID Required)'
	ch = raw_input('[+]  Enter Options : ')
	openLog()
	dbg = pydbg()
	dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, AccessViolationHandler)
	if int(ch) == 1:
		pn = raw_input ('[+] Enter process name (ex : IEXPLORE.EXE) : _ ' )
		for (pid,name) in dbg.enumerate_processes():
			if name == pn:
				try:
					print '[+] Attaching to ',pn ,pid
					dbg.attach(pid)
				except Exception,e:
					print '[+] [Error] Cannot Attach to process ',pn,pid
					exit()
	if int(ch) == 2:
		pid = raw_input('[+]  Enter PID : ')
		dbg.attach(int(pid))
	for api in target_apis:
		print '[+] Adding Hook for ',api
		try:
			t = api.split('!',1)
			hook_address = dbg.func_resolve_debuggee(t[0],t[1])
			addr_directory[hook_address] = api
			dbg.bp_set(hook_address,handler=sniffAPI)
		except Exception,e:
			print '[+] Failed'
	dbg.run()
if __name__ == '__main__':
	main()