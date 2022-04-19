import idaapi
import ida_funcs
import ida_bytes
import ida_dbg
import ida_ida
import idc
from idaapi import Choose

#------------------------DEBUG PART------------------------#
DEBUG = 3
INFO = 2
WARNING = 1

LogLevel = 0
def debug(*arg):
    if LogLevel >= DEBUG:
        unpack_and_print(arg)
        
def info(*arg):
    if LogLevel >= INFO:
        unpack_and_print(arg)
        
def warning(*arg):
    if LogLevel >= WARNING:
        unpack_and_print(arg)
            
def unpack_and_print(*arg):
    if arg is not None:
        arg = arg[0]
        msg = str(arg[0])
        for i in range(1, len(arg)):
            msg+= ", " + str(arg[i])
        print(msg)
#----------------------------------------------------------#
    
#------------------------CONSTANTS-------------------------#
MAX_NUMBER_FUNCTION_TO_SHOW = 1024

#https://hex-rays.com/products/ida/support/idadoc/276.shtml
class OperandType:
    GENERAL_REG = 1     # General Register (al, ax, es, ds...) reg
    DIRECT_MEM_REF = 2  # Direct Memory Reference  (DATA)      addr
    MEMORY_REF = 3      # Memory Ref [Base Reg + Index Reg]    phrase
    MEMORY_REG = 4      # Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
    IMMEDIATE_VALUE = 5 # Immediate Value 
    
#https://hex-rays.com/products/ida/support/idadoc/277.shtml
class OperandValueRegister:
    RSP = 4
    RBP = 5
#----------------------------------------------------------#

#-------------------FunctionAssemblyCalculator-------------#
#this class contains method helps with a calculation in function colde
class FunctionAssemblyCalculator:
    def iterateByPaddingToTheLastInstruction(ea):
        debug("iterateByPaddingToTheLastInstruction. Address: 0x{:X}".format(ea))
        for i in range(0,16):
            ea -= 1
            bytes = idc.get_bytes(ea, 1)
            
            debug('ea: 0x{:X}'.format(ea))
            debug(idc.get_bytes(ea, 1)[0])
            if idc.get_bytes(ea, 1)[0] == 0xCC or idc.get_bytes(ea, 1)[0] == 0x90:
                print('continue')
                continue
            break;
    def findRetInstruction(prev_ea):
        debug("iterateByPaddingToTheLastInstruction. Address: 0x{:X}".format(prev_ea))
        for i in range(0,256): 
            debug(idc.print_insn_mnem(prev_ea))
            if "ret" in idc.print_insn_mnem(prev_ea):
                debug("ret found. Address: 0x{:X}".format(prev_ea))
                break
                 
            if idaapi.decode_prev_insn(insn, prev_ea) != idaapi.BADADDR:
                prev_ea = idaapi.decode_prev_insn(insn, prev_ea)
            else:
                #ret is not at the end of function
                debug('ret is not at the end of function')
                #maybe 0xCC bytes?
                for i in range(0,16):
                    prev_ea -= 1
                    bytes = idc.get_bytes(prev_ea, 1)
                    
                    debug(idc.get_bytes(prev_ea, 1)[0])
                    if idc.get_bytes(prev_ea, 1)[0] == 0xCC or idc.get_bytes(prev_ea, 1)[0] == 0x90: #b'0xcc'
                        debug('continue')
                        continue
                    break;
                    
                if idaapi.decode_prev_insn(insn, prev_ea) == idaapi.BADADDR:
                    return (0, 0, 0)
                    
                curr_insn = idaapi.decode_prev_insn(insn, prev_ea)
                curr_insn += insn.size
                debug(idaapi.print_insn_mnem(curr_insn))
                prev_ea = curr_insn
        return prev_ea
        
    def findRspRbpDifference(curr_ea):
        difference = 0
        for i in range(0,256):
            mnem = idc.print_insn_mnem(curr_ea)
            debug(mnem)
            idaapi.decode_insn(insn, curr_ea)
            if mnem == 'push':
                push_offset = 8
                difference += push_offset
            elif mnem == 'sub':
                if idc.get_operand_value(curr_ea, 0) == OperandValueRegister.RSP and idc.get_operand_type(curr_ea, 1) == OperandType.IMMEDIATE_VALUE:
                    rsp_substraction = idc.get_operand_value(curr_ea, 1)
                    difference += rsp_substraction
            elif mnem == 'mov' or mnem == 'lea':
                #debug('type: ', idc.get_operand_type(curr_ea, 0), ' val: ', idc.get_operand_value(curr_ea, 0))
                debug( idc.generate_disasm_line(curr_ea, 0))
                if idc.get_operand_value(curr_ea, 0) == OperandValueRegister.RBP:
                    debug(mnem, ' type: ', idc.get_operand_type(curr_ea, 1), ' val: ', 'bp: 0x{:X}'.format(idc.get_operand_value(curr_ea, 1)))
                    
                    #case 1: mov
                    if mnem == 'mov':
                        if idc.get_operand_type(curr_ea, 1) == OperandType.GENERAL_REG and idc.get_operand_value(curr_ea, 1) == OperandValueRegister.RSP:
                            displacement = 0
                            
                    #case 2: lea
                    if mnem == 'lea':
                        if idc.get_operand_type(curr_ea, 1) == OperandType.MEMORY_REG:
                            if idc.get_operand_value(curr_ea, 1) > 0xF000000000000000:
                                displacement = 0x10000000000000000 - idc.get_operand_value(curr_ea, 1)
                                difference += displacement
                            else:
                                displacement = idc.get_operand_value(curr_ea, 1)
                                difference -= displacement
                    break
            
            curr_ea += insn.size
        return difference
#----------------------------------------------------------#
    
class MyChoose(Choose):
    def __init__(self, items, call_addr_list, title):
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
        self.call_addr_list = call_addr_list
        self.icon = 5
        self.selcount = 0
        self.modal = False
        
        #maybe add some popup names?
        #self.popup_names = ["First", "Second", "Third"]
	
    def OnInit(self):
        #debug("inited", str(self))
        return True

    def OnGetSize(self):
        n = len(self.items)
        #debug("getsize -> %d" % n)
        return n

    def OnGetLine(self, n):
        #debug("getline %d" % n)
        return self.items[n]
    
    def OnRefresh(self, n):
        start()
        
    def OnSelectLine(self, n):
        info("index: {}, addr: {}".format(n, hex(self.call_addr_list[n])))
        ida_kernwin.jumpto(self.call_addr_list[n])
        return (Choose.NOTHING_CHANGED, ) 
    
    #redundant
    # def OnCommand(self, n, cmd_id):
        # if cmd_id == self.cmd_jmp:
            # row = self.items[n]
            # idc.jumpto(int(row[0], 16))
			
    #def show(self):
        #self.Show()
        #self.cmd_jmp = self.AddCommand("Jump to call")

def extract_function_info_from_nearest_name(call_addr):
    if nearest_name:
        nearest_fun_debug_info = nearest_name.find(call_addr)
        
        if nearest_fun_debug_info:
            nearest_fun_debug_info_Ea, nearest_fun_debug_info_Name, index = nearest_fun_debug_info
            nearest_fun_debug_info_EndEa = find_func_end(nearest_fun_debug_info_Ea)
            debug("nearest_fun_debug_info_Name: {}, call_addr: {:X}, nearest_fun_debug_info_Ea: {:X}, nearest_fun_debug_info_EndEa: {:X}".format(nearest_fun_debug_info_Name, call_addr, nearest_fun_debug_info_Ea, nearest_fun_debug_info_EndEa))
            if call_addr >= nearest_fun_debug_info_Ea and call_addr <= nearest_fun_debug_info_EndEa:
                function_ea = nearest_fun_debug_info_Ea
                function_name = nearest_fun_debug_info_Name
                return (True, function_name, function_ea, nearest_fun_debug_info_EndEa)
                
    return (False, None, None, None)
    
def get_func_name_and_call_offset(call_addr):
    success, function_name, function_ea, function_end_ea = extract_function_info_from_nearest_name(call_addr)
    
    if success:
        #don't know why function_name sometimes is None. TODO check this
        if function_name is None:
            function_name = "unknown name"
            
        call_offset_in_function = "+0x{:X}".format(call_addr - function_ea)
    else:
        #failed to get info from nearest name
        function_info = idaapi.get_func(call_addr)
        
        if not function_info:
            ida_funcs.add_func(call_addr, idaapi.BADADDR)
            function_info = idaapi.get_func(call_addr)
            
        if function_info:
            function_ea = function_info.start_ea
            function_name = idc.get_func_name(function_ea)
            call_offset_int = call_addr - function_ea
                        
        call_offset_in_function = "+0x{:X}".format(call_offset_int)
    return (function_name, call_offset_in_function, function_ea, function_end_ea)

def get_info_about_call(call_addr, call_arg, stack_ptr, current_function = False):
    one_row = [] 
    
    call_addr_str = '{:08X}'.format(call_addr)
    #when print current function, then add " <ip>"
    if current_function:
        call_addr_str += " <ip>"
        
    #"Call Address" column
    one_row.append(call_addr_str)
    
    #"Call Argument", column
    one_row.append(call_arg)
    
    function_name, call_offset_in_function, _, _ = get_func_name_and_call_offset(call_addr)
    
    #when print current function, then add " <curr fun>"
    if current_function:
        function_name += " <curr fun>"
        
    #"Function name" column
    one_row.append(function_name)
    
    #when print current function, then add " <curr pos>"
    if current_function:
        call_offset_in_function += " <curr pos>"
        
    #Function offset" column
    one_row.append(call_offset_in_function)
    
    #"Segment" columns
    one_row.append(idaapi.get_segm_name(idaapi.getseg(call_addr)))
    
    #"Stack pointer" column
    one_row.append(" 0x{:X}".format(stack_ptr))
    
    return one_row

def check_previous_inst_is_call(return_addr, is_64bit):
    list_of_call_inst_lengths = [2, 3, 5, 6, 7]
    if is_64bit:
        list_of_call_inst_lengths.append(9)

    for call_length in list_of_call_inst_lengths:
        call_addr = return_addr - call_length
        
        try:
            if idaapi.is_call_insn(call_addr) and idc.create_insn(call_addr) and print_insn_mnem(call_addr) == "call":
                return (True, call_addr)
        except ValueError:
            continue
            
    return (False, None)

def set_version_and_platform_specific_elements():
    if idaapi.IDA_SDK_VERSION < 730:
        is_64bit =  idaapi.get_inf_structure().is_64bit()
        is_32bit =  idaapi.get_inf_structure().is_32bit() and not is_64bit
    elif idaapi.IDA_SDK_VERSION < 760:
        is_64bit = idaapi.inf_is_64bit()
        is_32bit = idaapi.inf_is_32bit() and not is_64bit
    else:
        is_64bit = idaapi.inf_is_64bit()
        is_32bit = idaapi.inf_is_32bit_exactly()
        
    return is_64bit

def calculate_caller_function_frame_info_x64(ea, sp, bp):
    PTR_SIZE = 8
    debug('ea: 0x{:X}'.format(ea))

    function_info = idaapi.get_func(ea)    
    if function_info:
        function_start_ea = function_info.start_ea
        function_end_ea = function_info.end_ea
    else:
        debug('function_info is None')
        _, _, function_start_ea, function_end_ea =  get_func_name_and_call_offset(ea)
    
    debug('function_start_ea: 0x{:X}, function_end_ea: 0x{:X}'.format(function_start_ea, function_end_ea))
    
    prev_ea = idaapi.decode_prev_insn(insn, function_end_ea)
    
    #often padding is present at the end of a function. Iterate by padding to the last function's instruction
    if prev_ea == idaapi.BADADDR:
        prev_ea = FunctionAssemblyCalculator.iterateByPaddingToTheLastInstruction(function_end_ea)
    
    #often ret is not at the end of the function but earlier. Find it
    prev_ea = FunctionAssemblyCalculator.findRetInstruction(prev_ea)
    
    #case 2: find a 'pop rbp' or 'add rsp, X'. Skip or pops
    
    #prev_ea point to 'ret' instruction. Get previous instrucion
    prev_ea = idaapi.decode_prev_insn(insn, prev_ea) 
    
    #if at the end some values are popped from stack then we need remember that 
    pop_instruction_number = 0
    while idc.print_insn_mnem(prev_ea) == "pop":
        debug(idc.get_operand_value(prev_ea, 0))
        
        if idc.get_operand_value(prev_ea, 0) == OperandValueRegister.RBP:
            #pop rbp found. Unfortunately I don't konw a value of current rbp so I need calculate.
            debug('CASE 2.1: calculate bp from function prolog')
            
            # there is a need to use rbp. Unfortunately we don't know a corelation between rsp and rbp, so we need use simple heuristic to deterimne it. 
            # Script will scan function from beginning looking for operation like: mov rbp, rsp or lea rbp, [rsp+0x00]
            difference = FunctionAssemblyCalculator.findRspRbpDifference(function_start_ea)
            
            #values for current funciton
            sp = bp + difference
            ret = idc.get_qword(sp)
            bp = sp - PTR_SIZE
            
            
            #Calculate registers for caller. ret takes a value from stack so I need change sp one more time
            sp += PTR_SIZE
            bp = idc.get_qword(bp) #get bp value from stack
            
            
            debug('sp: 0x{:X}'.format(sp))
            debug('bp: 0x{:X}'.format(bp))
            return (ret, sp, bp)
        else:
            prev_ea = idaapi.decode_prev_insn(insn, prev_ea)
            pop_instruction_number += 1
    
    #CASE 2.2: get func base pointer from rbp
    debug('CASE 2.2: calclulate bp from function epilog')
    debug(idc.print_insn_mnem(prev_ea), idc.get_operand_value(prev_ea, 0))
    
    old_sp = sp
    function_stack_size = 0
    
    mnem = idc.print_insn_mnem(prev_ea)
    arg_0_type = idc.get_operand_type(prev_ea,0)
    arg_0_value = idc.get_operand_value(prev_ea,0)
    arg_1_type = idc.get_operand_type(prev_ea,1)
    if mnem == "add" and arg_0_type == OperandType.GENERAL_REG and arg_0_value == OperandValueRegister.RSP and arg_1_type == OperandType.IMMEDIATE_VALUE:
        #this function has own place for stack. Count it
        function_stack_size = idc.get_operand_value(prev_ea, 1)
        sp += function_stack_size
        
    sp = sp + pop_instruction_number*PTR_SIZE
    ret = idc.get_qword(sp)
    
    #ret takes a value from stack so I need change sp one more time
    sp += PTR_SIZE
    
    #one more thing to do. Often previous instruction restoring rbp
    prev_ea = idaapi.decode_prev_insn(insn, prev_ea)
    mnem = idc.print_insn_mnem(prev_ea)
    arg_0_type = idc.get_operand_type(prev_ea,0)
    arg_0_value = idc.get_operand_value(prev_ea,0)
    arg_1_type = idc.get_operand_type(prev_ea,1)
    
    if mnem == 'mov' and arg_0_type == OperandType.GENERAL_REG and arg_0_value == OperandValueRegister.RBP and arg_1_type == OperandType.MEMORY_REG:
        bp = idc.get_qword(old_sp +  idc.get_operand_value(prev_ea, 1))
        
    debug(mnem, 'type0: ', arg_0_type, arg_0_value, 'type0: ', arg_1_type, idc.get_operand_value(prev_ea, 1))
    return (ret, sp, bp)

def get_all_calls():
    is_64bit = set_version_and_platform_specific_elements()
    
    call_list = []
    call_addr_list = []
    
    #check if stack segment is None. It's a problem
    if is_64bit:
        sp = cpu.Rsp
        ip = cpu.Rip
    else:
        sp = cpu.Esp
        ip = cpu.Eip
        
    if idaapi.getseg(cpu.Rsp) is None:
        warning("Stack segment is None")
        return False
        
    #information about current fun
    is_current_fun = True
    call_list.append(get_info_about_call(ip, "", sp, is_current_fun))
    call_addr_list.append(ip)
    
    #iterate by stack
    if is_64bit:
        #at the begging return address is set as a current ip
        return_addr = cpu.Rip
        curr_sp = cpu.Rsp
        curr_bp = cpu.Rbp
        
        for i in range(0, MAX_NUMBER_FUNCTION_TO_SHOW):
            return_addr, curr_sp, curr_bp = calculate_caller_function_frame_info_x64(return_addr, curr_sp, curr_bp)
            if return_addr == idaapi.BADADDR or return_addr == 0:
                break
            
            curr_segment = idaapi.getseg(return_addr)
            
            #segmenst must exists and be executable
            if not curr_segment or (curr_segment.perm & idaapi.SEGPERM_EXEC) == 0:
                continue
                
            is_call, curr_call_addr = check_previous_inst_is_call(return_addr, is_64bit)
            if not is_call:
                continue
                        
            #if bytes are not disassembled, then do it
            flags = ida_bytes.get_full_flags(curr_call_addr)
            if not ida_bytes.is_code(flags):
                idc.create_insn(curr_call_addr)
            
            #save a call argument
            call_list.append(get_info_about_call(curr_call_addr, print_operand(curr_call_addr, 0), return_addr))
            call_addr_list.append(curr_call_addr)
    else:
        curr_ebp = cpu.Ebp
        ptr_size = 4
        pfn_get_ptr = idc.get_wide_dword
        
        for i in range(0, MAX_NUMBER_FUNCTION_TO_SHOW):
            return_addr = pfn_get_ptr(curr_ebp + ptr_size)
            debug('ret: {:08X}'.format(return_addr))
            curr_ebp = pfn_get_ptr(curr_ebp)
            debug('ebp: {:08X}'.format(curr_ebp))
            
            if return_addr == idaapi.BADADDR or return_addr == 0:
                break
            
            curr_segment = idaapi.getseg(return_addr)
            
            #segmenst must exists and be executable
            if not curr_segment or (curr_segment.perm & idaapi.SEGPERM_EXEC) == 0:
                continue
                
            is_call, curr_call_addr = check_previous_inst_is_call(return_addr, is_64bit)
            if not is_call:
                continue
                        
            #if bytes are not disassembled, then do it
            flags = ida_bytes.get_full_flags(curr_call_addr)
            if not ida_bytes.is_code(flags):
                idc.create_insn(curr_call_addr)
            
            #save a call argument
            call_list.append(get_info_about_call(curr_call_addr, print_operand(curr_call_addr, 0), curr_ebp))
            call_addr_list.append(curr_call_addr)
    
    return True, call_list, call_addr_list

def init_nearest_names():
    debugNamesList = ida_name.get_debug_names(
        ida_ida.inf_get_min_ea(),
        ida_ida.inf_get_max_ea())
    
    #NearestName definition: <ida_dir>\python\3\ida_name.py, line: 1351
    #if your idapython NearestName is unavailable, comment this code
    return idaapi.NearestName(debugNamesList)
    
#program starts here
def start():
    process_is_suspended = False

    #check if process is suspended
    if idaapi.is_debugger_on():
        if idaapi.get_process_state() == -1:
            process_is_suspended = True
        else:
            idaapi.warning("Please suspend the debugger!")
    else:
        idaapi.warning("Please run the process!")
        
    #then start a stack checking
    if process_is_suspended:
        is_success, call_list, call_addr_list = get_all_calls()
        if is_success and call_list is not None:
            curr_thread = ida_dbg.get_current_thread()
            title = "CallStack - thread: {}".format(curr_thread)
            idaapi.close_chooser(title)
            c = MyChoose(call_list, call_addr_list, title)
            c.Show()
        else:
            idaapi.warning("Something wrong. There is no functions. Set DEBUG flag in the script and check what is going on")
       
insn = ida_ua.insn_t()
nearest_name = init_nearest_names()
debug(nearest_name)  
start()
