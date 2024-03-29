import idc
import json
import idaapi
from idautils import *

idc.auto_wait()
output = open("D:\\Project\\PythonProject\\datacon2021\\res_1015_48.txt", "a+")
register = idaapi.ph_get_regnames()

if "R0" in register:
    arch = "arm"
    pvar = ["R0", "R1", "R2", "R3", "[SP]"]       # ARM
    ppvar = ["R4", "R5"]
    inst = {
        "1": ["MOV", "LDR"],
        "2": ["STR"]
    }
elif "$a0" in register:
    arch = "mips"
    pvar = ["$a0", "$a1", "$a2", "$a3", "0x10($sp)"]    #MIPS
    ppvar = ["$v0", "$v1", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7"]
    inst = {
        "1": ["move", "addiu", "lw", "li"],
        "2": ["sw"],
        "3": ["lui"]
    }
elif "r15" in register:
    arch = "amd64"
    pvar = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]    #x86
    inst = {
        "1": ["mov", "lea"]
    }
else:
    print("NOT SUPPORT ARCH")
    exit(0)


def check(current_rip,start_ea,target_register_idx, check_const):
    print(f"Check Arg @ {hex(current_rip)}")
    if arch == "mips":
        current_rip += 4    # 对抗乱序执行
        local_vars = {
            "final_var": '',
            "current_var": pvar[target_register_idx],
            "data_base": 0
        }
        if target_register_idx > 3:
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
                current_inst = idc.print_insn_mnem(current_rip)
                operand_1_type = idc.get_operand_type(current_rip, 1)
                if ("\"" in asm) and (";" in asm or "#" in asm):
                    return 1 if check_const is True else 0
                if current_inst == "li" and operand_1_type in [0x5]:
                    maybe_str_off = idc.get_operand_value(current_rip, 1)
                    s = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                    if s is not None:
                        print("get_str", s)
                        return 1 if check_const is True else 0
                elif idc.print_operand(current_rip, 1) in ppvar:
                    local_vars["final_var"] = idc.print_operand(current_rip, 1)
                    print(hex(current_rip), asm)
                else:
                    return 0 if check_const is True else 1
            elif idc.print_insn_mnem(current_rip) in inst["3"] and idc.print_operand(current_rip, 0) == local_vars["final_var"]:
                if idc.print_insn_mnem(current_rip) == "lui":
                    hi = idc.get_operand_value(current_rip, 1)
                    if idc.print_insn_mnem(current_rip+4) == "addiu" and idc.print_operand(current_rip+4, 1) == local_vars["final_var"] and idc.get_operand_type(current_rip+4, 2) == 0x5:
                        maybe_str_off = idc.get_operand_value(current_rip+4, 2)+(hi << 16)
                        s = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                        if s is not None:
                            print("get_str", s)
                            return 1 if check_const is True else 0
            current_rip = idc.prev_head(current_rip)
        return 0
    elif arch == "arm":
        local_vars = {
            "final_var": '',
            "current_var": pvar[target_register_idx]
        }
        if target_register_idx > 3:
            while current_rip != start_ea:
                if idc.print_insn_mnem(current_rip) in inst["2"] and idc.op_hex(current_rip, 1) and idc.print_operand(
                        current_rip, 1) == local_vars["current_var"]:
                    local_vars["final_var"] = idc.print_operand(current_rip, 0)
                    break
                current_rip = idc.prev_head(current_rip)
        else:
            local_vars["final_var"] = local_vars["current_var"]
        while current_rip != start_ea:
            print(hex(current_rip), idc.print_insn_mnem(current_rip), "->", local_vars["final_var"])
            if idc.print_insn_mnem(current_rip) in inst["1"] and idc.print_operand(current_rip, 0) == local_vars["final_var"]:
                asm = idc.GetDisasm(current_rip)
                current_inst = idc.print_insn_mnem(current_rip)
                operand_1_type = idc.get_operand_type(current_rip, 1)
                if ("\"" in asm) and (";" in asm or "#" in asm):
                    return 1 if check_const is True else 0
                if current_inst == "LDR" and operand_1_type == 0x2:
                    maybe_str_off = idaapi.get_dword(idc.get_operand_value(current_rip, 1))
                    s = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                    if s is not None:
                        return 1 if check_const is True else 0
                elif idc.print_operand(current_rip, 1) in ppvar:
                    local_vars["final_var"] = idc.print_operand(current_rip, 1)
                    print("\t ->", hex(current_rip), asm)
                else:
                    return 0 if check_const is True else 1
            current_rip = idc.prev_head(current_rip)
        return 0 if check_const is True else 1


def check_with_va_args(current_rip, start_ea):
    print(f"Check Va Args @ {hex(current_rip)}")
    current_rip = current_rip + 4
    local_vars = {
        "isFmt": True,
        "cntFmt": 0,
        "currentRip": current_rip,
        "cntConst": 0,
        "final_var": pvar[0]
    }
    if arch == "mips":
        while current_rip != start_ea:
            print(hex(current_rip), idc.print_insn_mnem(current_rip))
            if idc.print_insn_mnem(current_rip) in inst["1"] and idc.print_operand(current_rip, 0) == local_vars["final_var"]:
                asm = idc.GetDisasm(current_rip)
                if ("\"" in asm) and (";" in asm or "#" in asm):

                    fmt_str_offset = idc.get_operand_value(current_rip, 1) + idaapi.get_imagebase()
                    fmt_str = idc.get_strlit_contents(fmt_str_offset, -1, idc.STRTYPE_C)
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
                elif idc.print_operand(current_rip, 1) in ppvar:
                    local_vars["final_var"] = idc.print_operand(current_rip, 1)
                    print(hex(current_rip), asm)
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
        return check(current_rip, start_ea, 0, True)


def check_vuln(ea,check_point):
    code_xrefs = CodeRefsTo(ea, False)
    for code_xref in code_xrefs:
        xref_function_address = idc.get_func_attr(code_xref, idc.FUNCATTR_START)
        if xref_function_address & 0xffffffff != 0xffffffff:
            if "va_args" not in check_point.keys() and "const" in check_point.keys():
                result = check(code_xref,xref_function_address,check_point['args']-1, check_point["const"])
                print(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref-idaapi.get_imagebase())},{result}')
                output.write(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref-idaapi.get_imagebase())},{result}\n')
            elif "va_args" in check_point.keys() and "const" in check_point.keys() and arch in ["mips"]:
                result = check_with_va_args(code_xref,xref_function_address)
                print(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref-idaapi.get_imagebase())},{result}')
                output.write(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},{result}\n')
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
            "function": "AES_cbc_encrypt",
            "args": 5,
            "const": False
        },
        {
            "function": "_AES_cbc_encrypt",
            "args": 5,
            "const": False
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
    for ea in Functions():
        functions[idc.get_func_name(ea)] = ea
    for check_point in check_list:
        vuln_function = check_point['function']
        if vuln_function in functions.keys():
            check_vuln(functions[vuln_function],check_point)
    output.close()
    idc.qexit(0)