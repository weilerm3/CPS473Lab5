from idaapi import *

class MyDbgHook(DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        if ea == 0x401228:
            password = ''
            for i in range(4202878, 4202894):
                if chr(Byte(i)) is None: break
                password += chr(Byte(i))
            print password
        if ea == 0x40123F:
            regval = idaapi.regval_t()
            if GetRegValue("ecx") == 0:
                regval.ival = 1
            else:
                regval.ival = 0
            idaapi.set_reg_val("ecx", regval)
        continue_process()
        return 0

    def dbg_step_over(self):
        eip = GetRegValue("EIP")

        self.steps += 1
        if self.steps >= 5:
            request_exit_process()
        else:
            request_step_over()
        return 0

# Remove an existing debug hook
try:
    if debughook:
        debughook.unhook()
except:
    pass

# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

AddBpt(0x401228)
AddBpt(0x40123F)

ep = GetLongPrm(INF_START_IP)
request_run_to(ep)

request_step_over()
# Start debugging
run_requests()
