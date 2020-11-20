"""
todo:
-add debug names
-add double clicking on each row
"""
import idaapi
import ida_funcs
import ida_bytes
import ida_dbg
import idc
from idaapi import Choose

class MyChoose(Choose):
    def __init__(self, items, title):
        Choose.__init__(
            self, 
            title, 
            [ ["Call Address", 10], ["Call Argument", 20], ["Caller function", 20], 
            ["Function offset", 10], ["Segment", 10], ["Stack pointer", 10] ], 
            flags = Choose.CH_RESTORE
                            | (Choose.CH_CAN_INS
                            | Choose.CH_CAN_DEL
                            | Choose.CH_CAN_EDIT
                            | Choose.CH_CAN_REFRESH),
            embedded  = None,
            width = None,
            height = None)
        
        self.items = items
        self.icon = 5
        self.selcount = 0
        self.modal = False
        
        #maybe add some popup names?
        #self.popup_names = ["First", "Second", "Third"]
	
    def OnInit(self):
        #print("inited", str(self))
        return True

    def OnGetSize(self):
        n = len(self.items)
        #print("getsize -> %d" % n)
        return n

    def OnGetLine(self, n):
        #print("getline %d" % n)
        return self.items[n]
		
    def OnCommand(self, n, cmd_id):
        if cmd_id == self.cmd_jmp:
            #print(str(n))
            row = self.items[n]
            idc.jumpto(int(row[0], 16))
			
    def show(self):
        #print("getline %d" % n)
        self.Show()
        self.cmd_jmp = self.AddCommand("Jump to call")


def getFuncInfo(callAddr, callArg, stackPtr, callAdrIsEsp = False):
    rowList = []
    callOffset = "" 
    
    callAddrStr = '{:08x}'.format(callAddr)
    if callAdrIsEsp:
        callAddrStr += " <ip>"
        
    #"Call Address" column
    rowList.append(callAddrStr)
    
    #"Call Argument", column
    rowList.append(callArg)
    
    funcName = ""
    functionInfo = idaapi.get_func(callAddr)
    if functionInfo:
        funcName = idc.get_func_name(callAddr)
        callOffset = "+" + hex(callAddr - functionInfo.start_ea)
    
    if callAdrIsEsp:
        funcName += " <curr fun>"
        
    #"Function name" column
    rowList.append(funcName)
    
    if callAdrIsEsp:
        callOffset += " <curr pos>"
        
    #Function offset" column
    rowList.append(callOffset)
    
    #"Segment" columns
    rowList.append(idaapi.get_segm_name(idaapi.getseg(callAddr)))
    
    #"Stack pointer" column
    rowList.append(" [" + hex(stackPtr) + "]")
    
    return rowList

def checkPreviousIsCall(returnAddr, is_64bit):
    listOfCallLengths = [2, 3, 5, 6, 7]
    if is_64bit:
        listOfCallLengths.append(9)

    for callLength in listOfCallLengths:
        callAddr = returnAddr - callLength
		
        try:
            if idaapi.is_call_insn(callAddr):
                #print(idc.create_insn(callAddr))
                return (True, callAddr)
        except ValueError:
            continue
            
    return (False, None)

def getAllCalls():
    if idaapi.IDA_SDK_VERSION < 730:
        is_64bit =  idaapi.get_inf_structure().is_64bit()
        is_32bit =  idaapi.get_inf_structure().is_32bit()
    else:
        is_64bit = idaapi.inf_is_64bit()
        is_32bit = idaapi.inf_is_32bit()

            
    if is_64bit:
        print("this is x64")
        stackPtr = cpu.Rsp
        instPtr = cpu.Rip
        ptrSize = 8
        getPtrFun = idc.get_qword
    elif is_32bit:
        print("this is x32")
        stackPtr = cpu.Esp
        instPtr = cpu.Eip
        ptrSize = 4
        getPtrFun = idc.get_wide_dword
    else:
        #something wrong
        return None 
    
    calls = []
    
    segment = idaapi.getseg(stackPtr)
    
    if not segment:
        idaapi.warning("Segment is None")
        return calls
        
    #information about current fun
    calls.append(getFuncInfo(instPtr, "", stackPtr, True))
    
    for sPtr in range(stackPtr, segment.end_ea + ptrSize, ptrSize):
        funReturnAddr = getPtrFun(sPtr)
        
        if funReturnAddr == idaapi.BADADDR:
            #something wrong
            continue
        
        #before 'funReturnAddr' should be call
        segment = idaapi.getseg(funReturnAddr)
        
        #check if segment exists
        if not segment:
            continue
            
        #segment must be executable
        if (segment.perm & idaapi.SEGPERM_EXEC) == 0:
            continue
			
        if funReturnAddr == idaapi.BADADDR:
            continue
            
        isCall, callAddr = checkPreviousIsCall(funReturnAddr, is_64bit)
        if not isCall:
            continue
                    
        #if bytes are not disassembled, then do it
        flags = ida_bytes.get_full_flags(callAddr)
        if not ida_bytes.is_code(flags):
            idc.create_insn(callAddr)
        
        #save a call argument
        calls.append(getFuncInfo(callAddr, print_operand(callAddr, 0), sPtr))
    
    return calls


#program starts here
processIsSuspended = False

#check if process is suspended
if idaapi.is_debugger_on():
    if idaapi.get_process_state() == -1:
        processIsSuspended = True
    else:
        idaapi.warning("Please suspend the debugger first!")
else:
    idaapi.warning("Please run the process first!")
    
#then start a stack checking
if processIsSuspended:  
    allCalls = getAllCalls()
    if allCalls:
        currThread = ida_dbg.get_current_thread()
        title = "CallStack - thread: {}".format(currThread)
        idaapi.close_chooser(title)
        c = MyChoose(allCalls, title)
        c.show()
