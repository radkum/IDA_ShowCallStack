import idaapi
import ida_funcs
import ida_bytes
import ida_dbg
import ida_ida
import idc
from idaapi import Choose

class MyChoose(Choose):
    def __init__(self, items, callsAddr, title):
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
        self.callsAddr = callsAddr
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
    
    def OnRefresh(self, n):
        start()
        
    def OnSelectLine(self, n):
        print("index: {}, addr: {}".format(n, hex(self.callsAddr[n])))
        ida_kernwin.jumpto(self.callsAddr[n])
        return (Choose.NOTHING_CHANGED, ) 
    
    #redundant
    # def OnCommand(self, n, cmd_id):
        # if cmd_id == self.cmd_jmp:
            # #print(str(n))
            # row = self.items[n]
            # idc.jumpto(int(row[0], 16))
			
    #def show(self):
        #print("getline %d" % n)
        #self.Show()
        #self.cmd_jmp = self.AddCommand("Jump to call")


def getFuncInfo(callAddr, callArg, stackPtr, nearestName, callAdrIsEsp = False):
    rowList = []
    callOffset = "" 
    
    callAddrStr = '{:08x}'.format(callAddr)
    #when print current function, then add " <ip>"
    if callAdrIsEsp:
        callAddrStr += " <ip>"
        
    #"Call Address" column
    rowList.append(callAddrStr)
    
    #"Call Argument", column
    rowList.append(callArg)
    
    if nearestName:
            funcInfo = nearestName.find(callAddr)
                    
    funcName = ""
    callOffset = ""
    
    if funcInfo:
        funcEa, funcName, funcIndex = funcInfo
        callOffset = "+" + hex(callAddr - funcEa)
    else:
        functionInfo = idaapi.get_func(callAddr)
        if functionInfo:
            funcName = idc.get_func_name(callAddr)
            callOffset = "+" + hex(callAddr - functionInfo.start_ea)
    
    #when print current function, then add " <curr fun>"
    if callAdrIsEsp:
        funcName += " <curr fun>"
        
    #"Function name" column
    rowList.append(funcName)
    
    #when print current function, then add " <curr pos>"
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
        is_32bit =  idaapi.get_inf_structure().is_32bit() and not is_64bit
    elif idaapi.IDA_SDK_VERSION < 760:
        is_64bit = idaapi.inf_is_64bit()
        is_32bit = idaapi.inf_is_32bit() and not is_64bit
    else:
        is_64bit = idaapi.inf_is_64bit()
        is_32bit = idaapi.inf_is_32bit_exactly()

            
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
    

    #get debug names
    #the full example: <ida_dir>\python\examples\debugging\show_debug_names.py
    debugNamesList = ida_name.get_debug_names(
        ida_ida.inf_get_min_ea(),
        ida_ida.inf_get_max_ea())
    
    #NearestName definition: <ida_dir>\python\3\ida_name.py, line: 1351
    #if your idapython NearestName is unavailable, comment this code
    nearestName = idaapi.NearestName(debugNamesList)
        
    calls = []
    callsAddr = []
    
    segment = idaapi.getseg(stackPtr)
    
    if not segment:
        idaapi.warning("Segment is None")
        return calls
        
    #information about current fun
    calls.append(getFuncInfo(instPtr, "", stackPtr, nearestName, True))
    callsAddr.append(instPtr)
    
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
            
        isCall, callAddr = checkPreviousIsCall(funReturnAddr, is_64bit)
        if not isCall:
            continue
                    
        #if bytes are not disassembled, then do it
        flags = ida_bytes.get_full_flags(callAddr)
        if not ida_bytes.is_code(flags):
            idc.create_insn(callAddr)
        
        #save a call argument
        calls.append(getFuncInfo(callAddr, print_operand(callAddr, 0), sPtr, nearestName))
        callsAddr.append(callAddr)
    
    return calls, callsAddr


#program starts here
def start():
    processIsSuspended = False

    #check if process is suspended
    if idaapi.is_debugger_on():
        if idaapi.get_process_state() == -1:
            processIsSuspended = True
        else:
            idaapi.warning("Please suspend the debugger!")
    else:
        idaapi.warning("Please run the process!")
        
    #then start a stack checking
    if processIsSuspended:
        allCalls, allCallsAdresses = getAllCalls()
        if allCalls:
            currThread = ida_dbg.get_current_thread()
            title = "CallStack - thread: {}".format(currThread)
            idaapi.close_chooser(title)
            c = MyChoose(allCalls, allCallsAdresses, title)
            c.Show()
            
start()
