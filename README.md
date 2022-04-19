# ShowCallStack IdaPython Script

Often I encounter a problem during debugging with IDA, because I want check a call stack but there is no such option. There is trace availibity, but it is not user friendly. Therefore I decided to invent ShowCallStack.py script with IDAPython, which display call stack during debugging.

I used some ideas from "CallStackWalk.py" (https://github.com/EiNSTeiN-/idapython/blob/master/Scripts/CallStackWalk.py), eg. idea of determining of instruction.

### Hotkey:
To add Hotkey to you IDA:

-place "ShowCallStack.py" in "<ida_dir>/python"  
-add to "<ida_dir>/idc/ida.idc" above main function following lines:
```
static showCallStack()  
{  
     //it's not important there are '/' or '\\'  
     auto pythonCommand = "exec(open('" + idadir() + "/python/ShowCallStack.py').read())";  
     auto ret = exec_python(pythonCommand);  
     if(ret == 0)  
     {  
          print("showCallStack() Success! ");  
     }  
     else  
     {  
          print(ret);  
     }  
}  
```     
-add at the beginning of main function this line:  
  
```
  //script is binded to "z" key. Change your shortcut if you want  
  AddHotkey("z", "showCallStack");  
```
