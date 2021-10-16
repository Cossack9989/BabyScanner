import idc
import json
import idaapi
from idautils import *

idc.auto_wait()
output = open("D:\\Project\\PythonProject\\datacon2021\\res_1016_22.txt", "a+")


class VulnScanner(object):

    def __init__(self):
        self.check_list = [
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
        self.register = idaapi.ph_get_regnames()
        if "R0" in self.register:
            self.arch = "arm"
        elif "$a0" in self.register:
            self.arch = "mips"
        elif "r15" in self.register:
            self.arch = "amd64"
        else:
            print("NO SUPPORT FOT THE ARCH")
            exit(0)

    def checkVuln(self, ea, check_point):
        code_xrefs = CodeRefsTo(ea, False)
        for code_xref in code_xrefs:
            xref_function_address = idc.get_func_attr(code_xref, idc.FUNCATTR_START)
            if xref_function_address & 0xffffffff != 0xffffffff:
                if "va_args" not in check_point.keys() and "const" in check_point.keys():
                    result = self.checkOneArg(code_xref, xref_function_address, check_point['args'] - 1, check_point["const"])
                    print(
                        f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},{result}'
                    )
                    output.write(
                        f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},{result}\n'
                    )
                elif "va_args" in check_point.keys() and "const" in check_point.keys():
                    result = self.checkVaArgs(code_xref, xref_function_address)
                    print(
                        f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},{result}'
                    )
                    output.write(
                        f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},{result}\n'
                    )
                else:
                    print(
                        f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},0'
                    )
                    output.write(
                        f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},0\n'
                    )
            else:
                pass

    def checkOneArg(self, current_ip, start_ea, target_register_idx, check_const):
        return 1

    def checkVaArgs(self, current_ip, start_ea):
        return 1


class MipsVulnScanner(VulnScanner):

    def __init__(self):
        super().__init__()
        self.pvar = ["$a0", "$a1", "$a2", "$a3", "0x10($sp)"]
        self.ppvar = ["$v0", "$v1", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7"]
        self.inst = {
            "1": ["move", "addiu", "lw", "li"],         # trace once while using $a?
            "2": ["sw"],                                # trace twice while using [SP,?]
            "3": [                                      # special inst set
                {
                    "mode":
                        {
                            "lui": "",
                            "addiu": {
                                "limit": {
                                    1: [["checkOperand", "o"]],
                                    2: [["checkOperandType", 0x5]]
                                }
                            }
                        },
                    "ip_interval": 1
                }
            ]
        }
        self.instInfo = {
            "addiu_pass_str_tracer_1": {
                "inst": "addiu",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_imm, "read": True},
                    2: {"type": idc.o_void}
                },
            },
            "addiu_pass_str_tracer_2": {
                "inst": "addiu",
                "operand": {
                    0: {"type": idc.o_reg},
                    1: {"type": idc.o_reg, "check": True},
                    2: {"type": idc.o_imm, "read": True}
                },
            },
            "addiu_pass_str_li_tracee": {
                "inst": "li",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_imm, "read": True},
                    2: {"type": idc.o_void}
                }
            },
            "addiu_pass_str_lui_tracee": {
                "inst": "lui",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_imm, "read": True},
                    2: {"type": idc.o_void}
                }
            }
        }

    def traceUpwardsInst(self, current_ip, start_ea, target_inst_info, target_var):
        while current_ip != start_ea:
            checkedInst = self.checkCurrentInst(current_ip, target_inst_info)
            if checkedInst[0] is True and checkedInst[1] == target_var:
                return current_ip, checkedInst[2]
            current_ip = idc.prev_head(current_ip)
        return -1, None

    def checkCurrentInst(self, current_ip, check_inst_info):
        # print("\t\tcheckCurrentInst", hex(current_ip), check_inst_info)
        local_vars = {
            "isTypeMatch": True,
            "toCheck": -1,
            "toRead": -1
        }
        if idc.print_insn_mnem(current_ip) == check_inst_info["inst"]:
            for idx in range(3):
                if check_inst_info["operand"][idx]["type"] != idc.get_operand_type(current_ip, idx):
                    local_vars["isTypeMatch"] = False
                    break
                if "check" in check_inst_info["operand"][idx].keys():
                    local_vars["toCheck"] = idx
                if "read" in check_inst_info["operand"][idx].keys():
                    local_vars["toRead"] = idx
            print(local_vars)
        else:
            return False, None, None
        if local_vars["isTypeMatch"] is True:
            return True, idc.print_operand(current_ip, local_vars["toCheck"]), idc.get_operand_value(current_ip, local_vars["toRead"] if local_vars["toRead"] != -1 else None)
        return False, None, None

    def checkOneArg(self, current_ip, start_ea, target_register_idx, check_const) -> (int, str):
        current_ip += 4
        local_vars = {
            "last_var": "",
            "curr_var": self.pvar[target_register_idx],
            "data_base": idaapi.get_imagebase(),
            "curr_inst": "",
            "string": ""
        }
        if target_register_idx > 3:
            while current_ip != start_ea:
                if idc.print_insn_mnem(current_ip) in self.inst["2"] and idc.op_hex(current_ip, 1) and idc.print_operand(current_ip, 1) == local_vars["curr_var"]:
                    # sw [sp+?], $r?获取$r?作为最终目标寄存器
                    local_vars["last_var"] = idc.print_operand(current_ip, 0)
                    break
                current_ip = idc.prev_head(current_ip)
        else:
            local_vars["last_var"] = local_vars["curr_var"]
        while current_ip != start_ea:
            local_vars["curr_inst"] = idc.print_insn_mnem(current_ip)
            if local_vars["curr_inst"] in self.inst["1"] and idc.print_operand(current_ip, 0) == local_vars["last_var"]:
                asm = idc.GetDisasm(current_ip)
                current_inst = idc.print_insn_mnem(current_ip)
                operand_1_type = idc.get_operand_type(current_ip, 1)
                if local_vars["curr_inst"] == "addiu":

                    # LOAD: 0040CDBC          li      $a0, dword_470000
                    # LOAD: 0040CDC0          la      $t9, system
                    # LOAD: 0040CDC4          nop
                    # LOAD: 0040CDC8          jr      $t9; system
                    # LOAD: 0040CDCC          addiu   $a0, (aBinKillall9Ppp - 0x470000)  # "/bin/killall -9 ppp_..."

                    check_inst = self.checkCurrentInst(current_ip, self.instInfo["addiu_pass_str_tracer_1"])
                    print("\tCheck addiu_pass_str_tracer_1", hex(current_ip), check_inst)
                    if check_inst[0] is True and check_inst[1] in self.ppvar+self.pvar and check_inst[2] is not None:
                        upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["addiu_pass_str_li_tracee"], check_inst[1])
                        print("\tUpwards addiu_pass_str_li_tracee", upwards_inst)
                        if upwards_inst[0] != -1 and upwards_inst[1] is not None:
                            maybe_str_off = (check_inst[2]+upwards_inst[1])&0xffffffff
                            local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                            return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                    # LOAD: 00419FE8          li      $v0, dword_470000
                    # LOAD: 00419FEC          nop
                    # LOAD: 00419FF0          addiu   $s0, $v0, (dword_46B99C - 0x470000)

                    check_inst = self.checkCurrentInst(current_ip, self.instInfo["addiu_pass_str_tracer_2"])
                    print("\tCheck addiu_pass_str_tracer_2", hex(current_ip), check_inst)
                    if check_inst[0] is True and check_inst[1] in self.ppvar+self.pvar and check_inst[2] is not None:
                        upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["addiu_pass_str_li_tracee"], check_inst[1])
                        print("\tUpwards addiu_pass_str_li_tracee", upwards_inst)
                        if upwards_inst[0] != -1 and upwards_inst[1] is not None:
                            maybe_str_off = (check_inst[2] + upwards_inst[1]) & 0xffffffff
                            local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                            return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                    # .text: 00400A98         lui     $v0, 0x40  # '@'
                    # .text: 00400A9C         addiu   $a0, $v0, (aPlaintextS - 0x400000)  # "plaintext: \"%s\"\n"

                    if check_inst[0] is True and check_inst[1] in self.ppvar+self.pvar and check_inst[2] is not None:
                        upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["addiu_pass_str_lui_tracee"], check_inst[1])
                        print("\tUpwards addiu_pass_str_lui_tracee", upwards_inst)
                        if upwards_inst[0] != -1 and upwards_inst[1] is not None:
                            maybe_str_off = (check_inst[2] + (upwards_inst[1] << 16)) & 0xffffffff
                            local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                            return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                elif idc.print_operand(current_ip, 1) in self.ppvar and idc.get_operand_value(current_ip, 2) == -0x1:
                    local_vars["last_var"] = idc.print_operand(current_ip, 1)
                    print("\tTracee-chg", hex(current_ip), asm)
                elif current_inst == "li" and operand_1_type == 0x5:
                    maybe_str_off = idc.get_operand_value(current_ip, 1)
                    s = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                    if s is not None:
                        print("\tget_str", s)
                        return (1, s) if check_const is True else (0, s)
                else:
                    return (0, '') if check_const is True else (1, '')
            current_ip = idc.prev_head(current_ip)
        return (0, '')

    def checkVaArgs(self, current_ip, start_ea):
        return 1



if __name__ == "__main__":
    functions = {}
    scanner = VulnScanner()
    for ea in Functions():
        functions[idc.get_func_name(ea)] = ea
    for check_point in scanner.check_list:
        vulnFunction = check_point["function"]
        if vulnFunction in functions.keys():
            if scanner.arch == "mips":
                mipsVulnScanner = MipsVulnScanner()
                mipsVulnScanner.checkVuln(functions[vulnFunction], check_point)
    output.close()
    idc.qexit(0)

