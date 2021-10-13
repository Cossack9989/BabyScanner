import idc
import json
import idaapi
import idautils

idc.auto_wait()
output = open("D:\\Project\\PythonProject\\datacon2021\\res.txt", "a+")
register = idaapi.ph_get_regnames()

if "R0" in register:
    arch = ["R0", "R1", "R2"]       # ARM
    inst = ["MOV","LDR"]
elif "$a0" in register:
    arch = ["$a0", "$a1", "$a2"]    #MIPS
    inst = ["move","addiu"]
elif "r15" in register:
    arch = ["rdi", "rsi", "rdx"]    #x86
    inst = ["mov", "add"]
else:
    print("NOT SUPPORT ARCH")
    exit(0)


def check(current_rip,start_ea,target_register, check_const):
    while current_rip != start_ea:
        if idc.print_insn_mnem(current_rip) in inst and idc.print_operand(current_rip,0) == target_register:
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


def check_vuln(ea,check_point):
    code_xrefs = idautils.CodeRefsTo(ea, False)
    for code_xref in code_xrefs:
        xref_function_address = idc.get_func_attr(code_xref, idc.FUNCATTR_START)
        if xref_function_address & 0xffffffff != 0xffffffff:
            result = check(code_xref,xref_function_address,arch[check_point['args']-1], check_point["const"])
            print(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref-idaapi.get_imagebase())},{result}')
            output.write(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref-idaapi.get_imagebase())},{result}\n')
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
            "args": 3,
            "const": False
        },
        {
            "function": "EVP_EncryptInit_ex",
            "args": 3,
            "const": False
        },
        {
            "function": "_EVP_DecryptInit_ex",
            "args": 3,
            "const": False
        },
        {
            "function": "_EVP_EncryptInit_ex",
            "args": 3,
            "const": False
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