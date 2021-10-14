import idc
import json
import idaapi
import idautils

idc.auto_wait()
output = open("D:\\Project\\PythonProject\\datacon2021\\res.txt", "a+")
register = idaapi.ph_get_regnames()

if "R0" in register:
    arch = "arm"
    pvar = ["R0", "R1", "R2", "R3", "[SP]"]       # ARM
    inst = {
        "1": ["MOV", "LDR"],
        "2": ["STR"]
    }
elif "$a0" in register:
    arch = "mips"
    pvar = ["$a0", "$a1", "$a2", "$a3", "0x10($sp)"]    #MIPS
    inst = {
        "1": ["move", "addiu", "lw", "li"],
        "2": ["sw"]
    }
elif "r15" in register:
    arch = "amd64"
    pvar = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]    #x86
    inst = ["mov", "lea"]
else:
    print("NOT SUPPORT ARCH")
    exit(0)


def check(current_rip,start_ea,target_register_idx, check_const):
    local_vars = {
        "final_var": '',
        "current_var": pvar[target_register_idx]
    }
    if target_register_idx > 3 and arch in ["arm", "mips"]:
        while current_rip != start_ea:
            if idc.print_insn_mnem(current_rip) in inst["2"] and idc.op_hex(current_rip, 1) and idc.print_operand(current_rip, 1) == local_vars["current_var"]:
                local_vars["final_var"] = idc.print_operand(current_rip, 0)
                break
            current_rip = idc.prev_head(current_rip)
    else:
        local_vars["final_var"] = local_vars["current_var"]
    while current_rip != start_ea:
        if idc.print_insn_mnem(current_rip) in inst["1"] and idc.print_operand(current_rip, 0) == local_vars["final_var"]:
            asm = idc.GetDisasm(current_rip)
            if check_const is True:
                if ("\"" in asm) and (";" in asm or "#" in asm):
                    return 1
                else:
                    return 0
            else:
                if ("\"" in asm) and (";" in asm or "#" in asm):
                    return 0
                else:
                    return 1
        current_rip = idc.prev_head(current_rip)
    return 0


def GetString(addr):
    string = ''
    while True:
        curByte = idaapi.get_byte(addr)
        if curByte == 0x00:
            break
        addr += 1
        string += chr(curByte)
    return string


def check_with_va_args(current_rip, start_ea):
    local_vars = {
        "isFmt": True,
        "cntFmt": 0,
        "currentRip": current_rip,
        "cntConst": 0
    }
    if arch == "mips":
        while current_rip != start_ea:
            print(current_rip, idc.print_insn_mnem(current_rip))
            if idc.print_insn_mnem(current_rip) in inst["1"] and idc.print_operand(current_rip, 0) == pvar[0]:
                asm = idc.GetDisasm(current_rip)
                if ("\"" in asm) and (";" in asm or "#" in asm):
                    current_analysis = {
                        "fmt_str_offset": 0
                    }
                    if idc.print_insn_mnem(current_rip) == "li":
                        current_analysis["fmt_str_offset"] = idc.get_operand_value(current_rip, 1)
                    else:
                        current_analysis["fmt_str_offset"] = idc.get_operand_value(current_rip, 1) + idaapi.get_imagebase()
                    fmt_str = GetString(current_analysis["fmt_str_offset"])
                    if fmt_str.find("%") == -1:
                        local_vars["isFmt"] = False
                        return 1
                    print(fmt_str)
                    for i in range(1, 7):
                        try:
                            testor = tuple([0]*i)
                            s = fmt_str % testor
                            local_vars["cntFmt"] = i
                            break
                        except Exception as e:
                            continue
                    break
                else:
                    return 0
            current_rip = idc.prev_head(current_rip)
        print(local_vars["cntFmt"])
        for var_idx in range(local_vars["cntFmt"]):
            local_vars_2 = {
                "final_var": '',
                "current_var": pvar[var_idx + 1]
            }
            current_rip = local_vars["currentRip"]
            if var_idx + 1 > 3:
                while current_rip != start_ea:
                    if idc.print_insn_mnem(current_rip) in inst["2"] and idc.op_hex(current_rip, 1) and idc.print_operand(
                            current_rip, 1) == local_vars_2["current_var"]:
                        local_vars_2["final_var"] = idc.print_operand(current_rip, 0)
                        break
                    current_rip = idc.prev_head(current_rip)
            else:
                local_vars_2["final_var"] = local_vars_2["current_var"]
            while current_rip != start_ea:
                if idc.print_insn_mnem(current_rip) in inst["1"] and idc.print_operand(current_rip, 0) == local_vars_2["final_var"]:
                    asm = idc.GetDisasm(current_rip)
                    if ("\"" in asm) and (";" in asm or "#" in asm):
                        local_vars["cntConst"] += 1
                    else:
                        return 0
                current_rip = idc.prev_head(current_rip)
        if local_vars["cntConst"] == local_vars["cntFmt"]:
            return 1
        else:
            return 0
    elif arch == "arm":
        return 0


def check_vuln(ea,check_point):
    code_xrefs = idautils.CodeRefsTo(ea, False)
    for code_xref in code_xrefs:
        xref_function_address = idc.get_func_attr(code_xref, idc.FUNCATTR_START)
        if xref_function_address & 0xffffffff != 0xffffffff:
            if "va_args" not in check_point.keys() and "const" in check_point.keys():
                result = check(code_xref,xref_function_address,check_point['args']-1, check_point["const"])
                print(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref-idaapi.get_imagebase())},{result}')
                output.write(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref-idaapi.get_imagebase())},{result}\n')
            elif "va_args" in check_point.keys() and "const" in check_point.keys():
                check_with_va_args(code_xref,xref_function_address)
            else:
                print(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},0')
                output.write(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},0\n')
        else:
            pass


if __name__ == '__main__':
    check_list = [
        {
            "function": "system",
            "args": 1,
            "const": True
        },
        {
            "function": "popen",
            "args": 1,
            "const": True
        },
        {
            "function": "sprintf",
            "args": 2,
            "const": True
        },
        {
            "function": "snprintf",
            "args": 3,
            "const": True
        },
        {
            "function": "_system",
            "args": 1,
            "const": True
        },
        {
            "function": "_popen",
            "args": 1,
            "const": True
        },
        {
            "function": "_sprintf",
            "args": 2,
            "const": True
        },
        {
            "function": "_snprintf",
            "args": 3,
            "const": True
        },
        {
            "function": "AES_set_encrypt_key",
            "args": 1,
            "const": False
        },
        {
            "function": "AES_set_decrypt_key",
            "args": 1,
            "const": False
        },
        {
            "function": "_AES_set_encrypt_key",
            "args": 1,
            "const": False
        },
        {
            "function": "_AES_set_decrypt_key",
            "args": 1,
            "const": False
        },
        {
            "function": "EVP_DecryptInit_ex",
            "args": 4,
            "const": False
        },
        {
            "function": "EVP_EncryptInit_ex",
            "args": 4,
            "const": False
        },
        {
            "function": "_EVP_DecryptInit_ex",
            "args": 4,
            "const": False
        },
        {
            "function": "_EVP_EncryptInit_ex",
            "args": 4,
            "const": False
        },
        {
            "function": "DES_set_key_checked",
        },
        {
            "function": "doSystem",
            "va_args": True,
            "const": True
        },
        {
            "function": "doSystembk",
            "va_args": True,
            "const": True
        },
        {
            "function": "doSystemCmd",
            "va_args": True,
            "const": True
        },
        {
            "function": "COMMAND",
            "va_args": True,
            "const": True
        }
    ]

    functions = {}
    for ea in idautils.Functions():
        functions[idc.get_func_name(ea)] = ea
    for check_point in check_list:
        vuln_function = check_point['function']
        if vuln_function in functions.keys():
            check_vuln(functions[vuln_function],check_point)
    output.close()
    idc.qexit(0)