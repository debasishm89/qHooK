'''
qHooK v0.1
Author : Debasish Mandal
Blog :http://www.debasish.in/
Twitter : https://twitter.com/debasishm89
 
qHooK is a very simple and straight forward python script (dependent on pydbg) 
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

#########################################################################################
# List of interesting APIS to be Hooked and monitored 
target_apis = {'kernel32.dll!LoadLibraryA':1,
				'kernel32.dll!LoadLibraryExA':3,
				'kernel32.dll!LoadLibraryExW':3,
				'kernel32.dll!LoadLibraryW':1,
				'kernel32.dll!LoadModule':2,
				'kernel32.dll!GetProcAddress':2,
				'kernel32.dll!VirtualProtect':4,
				'kernel32.dll!VirtualProtectEx':4,
				'kernel32.dll!WriteProcessMemory':5,
				'kernel32.dll!WriteFile':5,
				'kernel32.dll!WriteFileEx':5,
				'kernel32.dll!WinExec':2}
#########################################################################################
def openLog():
	f = open("call_log.csv", "wb")
	c = csv.writer(f)
	c.writerow(["Time Stamp","API Arguments","API Name","Return Address(Poi to Stack/Heap)","Stack Value(Poi to Stack/Heap)",  "Disassembly"   , "Raw Hex Bytes", "If printable Strings"])
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
	for arguments in range(0,target_apis[addr_directory[eip]]):
		temp = []
		stack_cont = hex(unpack('<L',dbg.read_process_memory( dbg.context.Esp + offset, 4 ))[0])
		try:
			d = dbg.read_process_memory( int (stack_cont,16), 10 )
			s_h = getregion(dbg,int(stack_cont,16))
		except Exception,e:
			d = 'N/A'
			s_h = 'N/A'
		temp.append(datetime.datetime.time(datetime.datetime.now()))
		temp.append('Argument : ' + str(arguments))
		temp.append(addr_directory[eip])													# API_NAME
		temp.append(ret_addr + '(' + getregion(dbg,int(ret_addr,16))  +')' )				# Return Address
		temp.append(stack_cont + '(' + s_h +')')											# Stack Cont
		temp.append(get_printable(d,'disasm'))												# Arg Disasm
		temp.append(get_printable(d,'hex'))													# Arg Hex Bytes
		temp.append(get_printable(d,'printable'))											# Arg Printable
		addToLog(temp)
		offset += 4
	addToLog(['','','','','','',''])
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