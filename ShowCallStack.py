import idaapi
import ida_funcs
import ida_bytes
import ida_dbg
import ida_ida
import idc
from idaapi import Choose

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
        print("index: {}, addr: {}".format(n, hex(self.call_addr_list[n])))
        ida_kernwin.jumpto(self.call_addr_list[n])
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

def extract_info_from_nearest_name(call_addr, nearest_name):
    if nearest_name:
        nearest_fun_debug_info = nearest_name.find(call_addr)
        
        if nearest_fun_debug_info:
            nearest_fun_debug_info_Ea, nearest_fun_debug_info_Name, index = nearest_fun_debug_info
            nearest_fun_debug_info_EndEa = find_func_end(nearest_fun_debug_info_Ea)
            #print("nearest_fun_debug_info_Name: {}, call_addr: {:X}, nearest_fun_debug_info_Ea: {:X}, nearest_fun_debug_info_EndEa: {:X}".format(nearest_fun_debug_info_Name, call_addr, nearest_fun_debug_info_Ea, nearest_fun_debug_info_EndEa))
            if call_addr >= nearest_fun_debug_info_Ea and call_addr <= nearest_fun_debug_info_EndEa:
                function_ea = nearest_fun_debug_info_Ea
                function_name = nearest_fun_debug_info_Name
                return (True, function_name, "+0x{:X}".format(call_addr - function_ea))
                
    return (False, None, None)
    
def get_func_name_and_call_offset(call_addr, nearest_name):
    function_name = "unknown name"
    call_offset_int = 0
    
    success, function_name, call_offset_in_function = extract_info_from_nearest_name(call_addr, nearest_name)

    if success:
        return (function_name, call_offset_in_function)
    else:
        #failed to get info from nearest name
        function_ea = idc.prev_head(call_addr, ida_ida.inf_get_min_ea()) 

        function_info = idaapi.get_func(function_ea)
        if not function_info:
            ida_funcs.add_func(function_ea, idaapi.BADADDR)
            function_info = idaapi.get_func(function_ea)
            
        if function_info:
            function_name = idc.get_func_name(function_ea)
            call_offset_int = call_addr - function_ea
                        
        call_offset_in_function = "+0x{:X}".format(call_offset_int)
        return (function_name, call_offset_in_function)

def get_info_about_call(call_addr, call_arg, stack_ptr, nearest_name, current_function = False):
    one_row = [] 
    
    call_addr_str = '{:08X}'.format(call_addr)
    #when print current function, then add " <ip>"
    if current_function:
        call_addr_str += " <ip>"
        
    #"Call Address" column
    one_row.append(call_addr_str)
    
    #"Call Argument", column
    one_row.append(call_arg)
    
    function_name, call_offset_in_function = get_func_name_and_call_offset(call_addr, nearest_name)
    
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

            
    if is_64bit:
        print("this is x64")
        stack_ptr = cpu.Rsp
        inst_ptr = cpu.Rip
        ptr_size = 8
        pfn_get_ptr = idc.get_qword
    elif is_32bit:
        print("this is x32")
        stack_ptr = cpu.Esp
        inst_ptr = cpu.Eip
        ptr_size = 4
        pfn_get_ptr = idc.get_wide_dword
        
    return (is_64bit, stack_ptr, inst_ptr, ptr_size, pfn_get_ptr)

def get_all_calls():
    is_64bit, stack_ptr, inst_ptr, ptr_size, pfn_get_ptr = set_version_and_platform_specific_elements()
    
    #get debug names
    #the full example: <ida_dir>\python\examples\debugging\show_debug_names.py
    debugNamesList = ida_name.get_debug_names(
        ida_ida.inf_get_min_ea(),
        ida_ida.inf_get_max_ea())
    
    #NearestName definition: <ida_dir>\python\3\ida_name.py, line: 1351
    #if your idapython NearestName is unavailable, comment this code
    nearest_name = idaapi.NearestName(debugNamesList)
        
    call_list = []
    call_addr_list = []
    
    stack_segment = idaapi.getseg(stack_ptr)
    
    if not stack_segment:
        idaapi.warning("Stack segment is None")
        return call_list
        
    #information about current fun
    call_list.append(get_info_about_call(inst_ptr, "", stack_ptr, nearest_name, True))
    call_addr_list.append(inst_ptr)
    
    for sp in range(stack_ptr, stack_segment.end_ea + ptr_size, ptr_size):
        return_addr = pfn_get_ptr(sp)
        
        if return_addr == idaapi.BADADDR:
            continue
        
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
        call_list.append(get_info_about_call(curr_call_addr, print_operand(curr_call_addr, 0), sp, nearest_name))
        call_addr_list.append(curr_call_addr)
    
    return call_list, call_addr_list


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
        call_list, call_addr_list = get_all_calls()
        if call_list:
            curr_thread = ida_dbg.get_current_thread()
            title = "CallStack - thread: {}".format(curr_thread)
            idaapi.close_chooser(title)
            c = MyChoose(call_list, call_addr_list, title)
            c.Show()
            
start()
