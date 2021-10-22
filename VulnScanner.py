import idc
import json
import idaapi
import networkx as nx
from idautils import *

idc.auto_wait()
output = open("D:\\Project\\PythonProject\\datacon2021\\res_1021_test.txt", "a+")


class VulnScanner(object):

    def __init__(self, CmdiMode=False):
        self.CmdiMode = CmdiMode
        self.cmdi_pre_func_list = ['sprintf', "_sprintf", ".sprintf", "snprintf", "_snprintf", ".snprintf", "strcpy", "_strcpy", ".strcpy", "strncpy", "_strncpy", ".strncpy", "memcpy", "_memcpy", ".memcpy"]
        self.pvar = []
        self.ppvar = []
        self.inst = {}
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
                    print(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},{result[0]}')
                    if self.arch == "amd64" and idc.get_func_name(ea).startswith("."):
                        func_name = "_" + idc.get_func_name(ea)[1:]
                        output.write(f'{idaapi.get_root_filename()},{func_name},{hex(code_xref - idaapi.get_imagebase())},{result[0]}\n')
                    else:
                        output.write(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},{result[0]}\n')
                elif "va_args" in check_point.keys() and "const" in check_point.keys():
                    result = self.checkVaArgs(code_xref, xref_function_address)
                    print(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},{result[0]}')
                    output.write(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},{result[0]}\n')
                else:
                    print(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},0')
                    output.write(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},0\n')
            else:
                print(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},1')
                if self.arch == "amd64" and idc.get_func_name(ea).startswith("."):
                    func_name = "_" + idc.get_func_name(ea)[1:]
                    output.write(f'{idaapi.get_root_filename()},{func_name},{hex(code_xref - idaapi.get_imagebase())},1\n')
                else:
                    output.write(f'{idaapi.get_root_filename()},{idc.get_func_name(ea)},{hex(code_xref - idaapi.get_imagebase())},1\n')

    def traceUpwardsInst(self, current_ip, start_ea, target_inst_info, target_var):
        while current_ip != start_ea:
            print("\t\t\t", hex(current_ip), idc.GetDisasm(current_ip))
            checkedInst = self.checkCurrentInst(current_ip, target_inst_info)
            # print(checkedInst[1], ";", target_var)
            if checkedInst[0] is True and checkedInst[1] == target_var:
                return current_ip, checkedInst[2]
            current_ip = idc.prev_head(current_ip)
        return -1, None

    def checkCurrentInst(self, current_ip, check_inst_info):
        local_vars = {
            "isTypeMatch": True,
            "toCheck": -1,
            "toRead": -1,
            "checkRes": None
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
        else:
            return False, None, None
        if local_vars["isTypeMatch"] is True:
            if local_vars["toCheck"] != -1:
                if check_inst_info["operand"][local_vars["toCheck"]]["type"] == idc.o_displ:
                    for reg in self.ppvar + self.pvar:
                        if reg in idc.print_operand(current_ip, local_vars["toCheck"]):
                            local_vars["checkRes"] = reg
                            break
                else:
                    local_vars["checkRes"] = idc.print_operand(current_ip, local_vars["toCheck"])
                return True, local_vars["checkRes"], idc.get_operand_value(current_ip, local_vars["toRead"] if local_vars["toRead"] != -1 else None)
        return False, None, None

    def isStrFmtIdx(self, fmt_str: bytes, idx):
        fmt_str = fmt_str.decode("latin-1")
        l = fmt_str.split("%")
        try:
            if l[idx+1].startswith('s') or l[idx+1].startswith('[') or l[idx+1].startswith('*s') or l[idx+1].startswith('*[') or l[idx+1].startswith('*.'): # %-8s
                return True
        except Exception as e:
            print(str(Exception), str(e))
        return False

    def checkOneArg(self, current_ip, start_ea, target_register_idx, check_const):
        return 1, b''

    def checkVaArgs(self, current_ip, start_ea, start_reg_idx=0):
        return 1, b''

    def genCfgPaths(self, start_ip, func_addr):
        # def findAllPath(graph, block_start, block_end, path=None):
        #     print(block_start, block_end, path)
        #     if path is None:
        #         path = []
        #     path = path + [block_start]
        #     if block_start == block_end:
        #         return path
        #     paths = []
        #     for node in graph[block_start]:
        #         if node not in path:
        #             new_paths = findAllPath(graph, node, block_end, path)
        #             for new_path in new_paths:
        #                 paths.append(new_path)
        #                 print(new_path)
        #     return paths
        local_vars = {"block_now": (0, 0xffffffff), "block_start": (0, 0xffffffff)}
        block_list = [block for block in idaapi.FlowChart(idaapi.get_func(func_addr))]
        G = nx.DiGraph()
        for cb in block_list:
            if cb.id == 0:
                local_vars["block_start"] = (cb.start_ea, cb.end_ea - 4)
            if cb.start_ea <= start_ip < cb.end_ea:
                local_vars["block_now"] = (cb.start_ea, cb.end_ea - 4)
                break
        if local_vars["block_now"] == local_vars["block_start"]:
            return [[local_vars["block_now"]]]
        for cb in block_list:
            for ncb in cb.succs():
                if (cb.start_ea, cb.end_ea - 4) != (ncb.start_ea, ncb.end_ea - 4):
                    G.add_edge((cb.start_ea, cb.end_ea - 4), (ncb.start_ea, ncb.end_ea - 4))
        print("Done")
        return [path for path in nx.all_simple_paths(G, source=local_vars["block_start"], target=local_vars["block_now"])]


class ArmVulnScanner(VulnScanner):

    def __init__(self, CmdiMode=False):
        super().__init__(CmdiMode=CmdiMode)
        self.pvar = ["R0", "R1", "R2", "R3", "[SP]", "[SP,#4]", "[SP,#8]", "[SP,#0xC]", "[SP,#0x10]"]
        self.ppvar = ["R4", "R5", "R6", "R7"]
        self.inst = {
            "1": ["MOV", "LDR", "ADD", "MOVT", "MOVW", "LDRGE", "LDREQ"],
            "2": ["STR"],
            "c": ["BL"]
        }
        self.instInfo = {
            "add_pass_str_tracer": {
                "inst": "ADD",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_reg, "read": True},
                    2: {"type": idc.o_reg}
                },
            },
            "add_pass_str_tracer2": {
                "inst": "ADD",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_reg},
                    2: {"type": idc.o_imm, "read": True}
                }
            },
            "add_pass_str_ldr_tracee": {
                "inst": "LDR",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_mem, "read": True},
                    2: {"type": idc.o_void}
                }
            },
            "movw_pass_str_tracer_and_tracee": {
                "inst": "MOVW",
                "operand": {
                    0: {"type": idc.o_reg, "check": True, "read": True},
                    1: {"type": idc.o_imm},
                    2: {"type": idc.o_void}
                }
            },
            "movt_pass_str_tracer_and_tracee": {
                "inst": "MOVT",
                "operand": {
                    0: {"type": idc.o_reg, "check": True, "read": True},
                    1: {"type": idc.o_imm},
                    2: {"type": idc.o_void}
                }
            },
            "ldr_pass_str_tracer": {
                "inst": "LDR",
                "operand": {
                    0: {"type": idc.o_reg},
                    1: {"type": idc.o_displ, "check": True, "read": True},
                    2: {"type": idc.o_void}
                }
            },
            "ldr_pass_str_ldr_tracee": {
                "inst": "LDR",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_mem, "read": True},
                    2: {"type": idc.o_void}
                }
            }
        }
        self.tracee_var = []
        self.CmdiModeConfirm = False
        self.CmdiModeConfirmPre = False

    def resetCmdiMode(self):
        self.CmdiMode = True
        self.CmdiModeConfirm = False
        self.CmdiModeConfirmPre = False
        self.tracee_var.pop(-1)

    def getGlobalOffsetTable(self):
        if "_GLOBAL_OFFSET_TABLE_" in [name[1] for name in Names()]:
            try:
                idx = [name[1] for name in Names()].index("_GLOBAL_OFFSET_TABLE_")
                return [name[0] for name in Names()][idx]
            except Exception as e:
                print(str(Exception))
        return None

    def checkOneArg(self, current_ip, start_ea, target_register_idx, check_const):
        origin_current_ip = current_ip
        local_vars = {
            "last_var": "",
            "curr_var": self.pvar[target_register_idx],
            "data_base": idaapi.get_imagebase(),
            "curr_inst": "",
            "string": "",
            "pred_func": 0,
            "pred_func_name": '',
            "cmdi_mode_res": None,
            "trace_1_stage_paths": [],
            "orig_ip": 0,
            "orig_ag": ''
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
        block_list = [(block.start_ea, block.end_ea, block) for block in idaapi.FlowChart(idaapi.get_func(start_ea))]
        for block in block_list:
            if block[0] <= current_ip <= block[1]:
                for pred_block in [(pred.start_ea-4, pred.end_ea-4) for pred in block[2].preds()]:
                    local_vars["trace_1_stage_paths"].append({"go": block[0], "to": pred_block[1], "end": pred_block[0]})
                if len(local_vars["trace_1_stage_paths"]) == 0:
                    local_vars["trace_1_stage_paths"].append({"end": block[0]})
                break
        if len(local_vars["trace_1_stage_paths"]) == 0:
            local_vars["trace_1_stage_paths"].append({"end": 0xffffffff})
        local_vars["orig_ip"] = current_ip
        local_vars["orig_ag"] = local_vars["last_var"]
        for path in local_vars["trace_1_stage_paths"]:
            current_ip = local_vars["orig_ip"]
            local_vars["last_var"] = local_vars["orig_ag"]
            while current_ip != start_ea and current_ip != path["end"] and current_ip-4 != local_vars["orig_ip"]:
                local_vars["curr_inst"] = idc.print_insn_mnem(current_ip)
                print("CURR_INST", local_vars["curr_inst"], self.CmdiMode, hex(origin_current_ip), hex(current_ip))
                if local_vars["curr_inst"] in self.inst["c"] and self.CmdiMode is True and current_ip != local_vars["orig_ip"]:
                    print("\tGET FUNC BY TRACER")
                    print("\tTracee is", local_vars["last_var"])
                    self.tracee_var.append(local_vars["last_var"])
                    bl_addr = idc.get_operand_value(current_ip, 0)
                    func_name = idc.get_func_name(bl_addr)
                    if func_name in self.cmdi_pre_func_list:
                        local_vars["pred_func"] = bl_addr
                        local_vars["pred_func_name"] = func_name
                        self.CmdiMode = False
                        self.CmdiModeConfirmPre = True
                        if local_vars["pred_func_name"] in ["sprintf", "_sprintf", ".sprintf", "strcpy", "_strcpy", ".strcpy", "strncpy", "_strncpy", ".strncpy", "memcpy", "_memcpy", ".memcpy"]:
                            local_vars["cmdi_mode_res"] = self.checkVaArgs(current_ip, start_ea, start_reg_idx=1)
                            if self.CmdiModeConfirm is True:
                                self.resetCmdiMode()
                                return local_vars["cmdi_mode_res"]
                        elif local_vars["pred_func_name"] in ["snprintf", "_snprintf", ".snprintf"]:
                            local_vars["cmdi_mode_res"] = self.checkVaArgs(current_ip, start_ea, start_reg_idx=2)
                            if self.CmdiModeConfirm is True:
                                self.resetCmdiMode()
                                return local_vars["cmdi_mode_res"]
                        self.resetCmdiMode()
                if local_vars["curr_inst"] in self.inst["1"] and idc.print_operand(current_ip, 0) == local_vars["last_var"]:
                    asm = idc.GetDisasm(current_ip)
                    current_inst = idc.print_insn_mnem(current_ip)
                    operand_1_type = idc.get_operand_type(current_ip, 1)
                    operand_2_type = idc.get_operand_type(current_ip, 2)
                    if idc.print_operand(current_ip, 1) in self.ppvar+self.pvar and idc.get_operand_value(current_ip, 2) == -0x1:
                        local_vars["last_var"] = idc.print_operand(current_ip, 1)
                        print("\tTracee-chg", hex(current_ip), asm)
                        if len(self.tracee_var) != 0 and self.tracee_var[-1] == local_vars["last_var"] and self.CmdiModeConfirmPre is True:
                            print(f"\t[Get Tracee In Cmdi Mode]{self.tracee_var[-1]}")
                            self.CmdiModeConfirm = True
                    elif local_vars["curr_inst"] == "LDR":
                        if operand_1_type == idc.o_mem:
                            maybe_str_off = idaapi.get_dword(idc.get_operand_value(current_ip, 1))
                            local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                            return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                        check_inst = self.checkCurrentInst(current_ip, self.instInfo["ldr_pass_str_tracer"])
                        if check_inst[0] is True and check_inst[1] in self.ppvar + self.pvar:
                            upwards_inst = self.traceUpwardsInst(current_ip - 4, start_ea,
                                                                 self.instInfo["ldr_pass_str_ldr_tracee"],
                                                                 check_inst[1])
                            print("\tUpwards ldr_pass_str_ldr_tracee", upwards_inst)
                            if upwards_inst[0] != -1 and upwards_inst[1] is not None and check_inst[2] is not None:
                                maybe_str_off = (idaapi.get_dword(upwards_inst[1] + check_inst[2])) & 0xffffffff
                                print("Maybe Str", upwards_inst[1], hex(maybe_str_off))
                                local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                                return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                        elif check_inst[1] not in self.ppvar + self.pvar and check_inst[1] is not None:
                            return (0, b'') if check_const is True else (1, b'')
                    elif local_vars["curr_inst"] == "LDRGE" and operand_1_type == idc.o_mem:
                        maybe_str_off = idaapi.get_dword(idc.get_operand_value(current_ip, 1))
                        local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                        return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                    elif local_vars["curr_inst"] == "LDREQ" and operand_1_type == idc.o_mem:
                        maybe_str_off = idaapi.get_dword(idc.get_operand_value(current_ip, 1))
                        local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                        return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                    elif local_vars["curr_inst"] == "MOV" and operand_1_type == idc.o_imm:
                        maybe_str_off = idc.get_operand_value(current_ip, 1)
                        local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                        return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                    elif local_vars["curr_inst"] == "ADD":
                        check_inst = self.checkCurrentInst(current_ip, self.instInfo["add_pass_str_tracer"])
                        print("\tCheck add_pass_str_tracer", hex(current_ip), check_inst)
                        if check_inst[0] is True and check_inst[1] in self.ppvar + self.pvar:
                            upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["add_pass_str_ldr_tracee"], check_inst[1])
                            print("\tUpwards add_pass_str_ldr_tracee", upwards_inst)
                            if upwards_inst[0] != -1 and upwards_inst[1] is not None and idc.print_operand(current_ip, 1) != "PC":
                                maybe_str_off = (idaapi.get_dword(upwards_inst[1]) + self.getGlobalOffsetTable()) & 0xffffffff
                                print("Maybe Str", upwards_inst[1], hex(maybe_str_off))
                                local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                                return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                        elif check_inst[1] not in self.ppvar+self.pvar and check_inst[1] is not None:
                            return (0, b'') if check_const is True else (1, b'')
                        check_inst = self.checkCurrentInst(current_ip, self.instInfo["add_pass_str_tracer2"])
                        print("\tCheck add_pass_str_tracer2", hex(current_ip), check_inst)
                        print("Maybe sp tracee")
                        if check_inst[0] is True and check_inst[1] == "SP" and check_inst[2] is not None:
                            tmp_reg = f"[SP,#0x{check_inst[2]:X}]"
                            local_vars["last_var"] = tmp_reg
                            if local_vars["last_var"] not in self.ppvar:
                                self.ppvar.append(tmp_reg)
                            print("\tTracee-chg", hex(current_ip), asm)
                            if len(self.tracee_var) != 0 and self.tracee_var[-1] == local_vars["last_var"] and self.CmdiModeConfirmPre is True:
                                self.CmdiModeConfirm = True
                    elif local_vars["curr_inst"] == "MOVT":
                        check_inst = self.checkCurrentInst(current_ip, self.instInfo["movt_pass_str_tracer_and_tracee"])
                        print("\tCheck movt_pass_str_tracer_and_tracee", hex(current_ip), check_inst)
                        if check_inst[0] is True and check_inst[1] in self.ppvar + self.pvar and check_inst[2] is not None:
                            upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["movw_pass_str_tracer_and_tracee"], check_inst[1])
                            print("\tUpwards movw_pass_str_tracer_and_tracee", upwards_inst)
                            if upwards_inst[0] != -1 and upwards_inst[1] is not None:
                                maybe_str_off = ((upwards_inst[1] + (check_inst[2]<<16))&0xffffffff)
                                local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                                return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                    elif local_vars["curr_inst"] == "MOVW":
                        check_inst = self.checkCurrentInst(current_ip, self.instInfo["movw_pass_str_tracer_and_tracee"])
                        print("\tCheck movw_pass_str_tracer_and_tracee", hex(current_ip), check_inst)
                        if check_inst[0] is True and check_inst[1] in self.ppvar + self.pvar and check_inst[2] is not None:
                            upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["movt_pass_str_tracer_and_tracee"], check_inst[1])
                            print("\tUpwards movt_pass_str_tracer_and_tracee", upwards_inst)
                            if upwards_inst[0] != -1 and upwards_inst[1] is not None:
                                maybe_str_off = ((check_inst[2] + (upwards_inst[1]<<16))&0xffffffff)
                                local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                                return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                    # else:
                    #     return (0, b'') if check_const is True else (1, b'')
                if "go" in path.keys() and "to" in path.keys():
                    if current_ip == path["go"]:
                        current_ip = path["to"]
                    else:
                        current_ip = idc.prev_head(current_ip)
                else:
                    current_ip = idc.prev_head(current_ip)
        return 0, b''

    def checkVaArgs(self, current_ip, start_ea, start_reg_idx=0):
        local_vars = {
            "cntFmt": 0,
            "filling": '',
        }
        if self.CmdiMode is False and self.CmdiModeConfirmPre is True:
            print("arg 0 start")
            self.checkOneArg(current_ip, start_ea, 0, True)
            print("arg 0 end")
            self.CmdiModeConfirmPre = False
        firstArg = self.checkOneArg(current_ip, start_ea, start_reg_idx, True)
        print(firstArg)
        if firstArg[0] == 1 and firstArg[1] is not None and len(firstArg[1]) != 0:
            fmt_str = firstArg[1].decode("latin-1")
            if fmt_str.find("%") == -1:
                return 1, fmt_str.encode("latin-1")
            print("\tFMT STR:", fmt_str)
            for i in range(1, 7):
                try:
                    testor = tuple([0] * i)
                    s = fmt_str % testor
                    local_vars["cntFmt"] = i
                    break
                except Exception as e:
                    continue
        else:
            return 0, b''
        filling = []
        for var_idx in range(local_vars["cntFmt"]):
            print(f"====================={str(var_idx + 1)}========================")
            if self.isStrFmtIdx(firstArg[1], var_idx) is True:
                curr_var = self.checkOneArg(current_ip, start_ea, var_idx + start_reg_idx + 1, True)
                if curr_var[0] == 0:
                    return 0, b''
                if curr_var[1] is None:
                    filling.append("[UNKNOWN]")
                else:
                    filling.append(curr_var[1].decode("latin-1"))
        try:
            local_vars["filling"] = fmt_str % tuple(filling)
        except Exception as e:
            print(str(Exception), str(e))
            return 1, b''
        return 1, local_vars["filling"].encode("latin-1")


class X64VulnScanner(VulnScanner):

    def __init__(self, CmdiMode=False):
        super().__init__(CmdiMode=CmdiMode)
        self.pvar1 = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        self.pvar2 = ["edi", "esi", "edx", "ecx"]
        self.ppvar = []
        self.inst = {
            "1": ["mov", "lea"]
        }

    def checkOneArg(self, current_ip, start_ea, target_register_idx, check_const):
        local_vars = {
            "last_var": "",
            "curr_var1": self.pvar1[target_register_idx],
            "curr_var2": self.pvar2[target_register_idx],
            "data_base": idaapi.get_imagebase(),
            "curr_inst": "",
            "string": ""
        }
        local_vars["last_var"] = [local_vars["curr_var1"], local_vars["curr_var2"]]
        while current_ip != start_ea:
            local_vars["curr_inst"] = idc.print_insn_mnem(current_ip)
            if local_vars["curr_inst"] in self.inst["1"] and idc.print_operand(current_ip, 0) in local_vars["last_var"]:
                asm = idc.GetDisasm(current_ip)
                current_inst = idc.print_insn_mnem(current_ip)
                operand_1_type = idc.get_operand_type(current_ip, 1)
                if idc.print_operand(current_ip, 1) in self.ppvar+self.pvar and idc.get_operand_value(current_ip, 2) == -0x1:
                    tmp_var = idc.print_operand(current_ip, 1)
                    if tmp_var.startswith("r"):
                        local_vars["last_var"] = [tmp_var, tmp_var.replace("r", "e")]
                    elif tmp_var.startswith("e"):
                        local_vars["last_var"] = [tmp_var.replace("e", "r"), tmp_var]
                    else:
                        local_vars["last_var"] = [tmp_var, tmp_var]
                    print("\tTracee-chg", hex(current_ip), asm)
                elif local_vars["curr_inst"] == "mov" and idc.get_operand_type(current_ip, 1) == idc.o_imm:
                    maybe_str_off = idc.get_operand_value(current_ip, 1)
                    local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                    return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                else:
                    return (0, b'') if check_const is True else (1, b'')
            current_ip = idc.prev_head(current_ip)
        return 0, b''

    def checkVaArgs(self, current_ip, start_ea, start_reg_idx=0):
        local_vars = {
            "cntFmt": 0,
            "cntConst": 0,
        }
        firstArg = self.checkOneArg(current_ip, start_ea, start_reg_idx, True)
        print(firstArg)
        if firstArg[0] == 1 and firstArg[1] is not None and len(firstArg[1]) != 0:
            fmt_str = firstArg[1].decode("latin-1")
            if fmt_str.find("%") == -1:
                return 1
            print("\tFMT STR:", fmt_str)
            for i in range(1, 7):
                try:
                    testor = tuple([0] * i)
                    s = fmt_str % testor
                    local_vars["cntFmt"] = i
                    break
                except Exception as e:
                    continue
        else:
            return 0
        for var_idx in range(local_vars["cntFmt"]):
            print(f"====================={str(var_idx + 1)}========================")
            if self.isStrFmtIdx(firstArg[1], var_idx) is True:
                curr_var = self.checkOneArg(current_ip, start_ea, var_idx + 1, True)
                if curr_var[0] == 0:
                    return 0
        return 1


class MipsVulnScanner(VulnScanner):

    def __init__(self, CmdiMode=False):
        super().__init__(CmdiMode=CmdiMode)
        self.pvar = ["$a0", "$a1", "$a2", "$a3", "0x10($sp)", "0x14($sp)", "0x18($sp)", "0x1c($sp)", "0x20($sp)"]
        self.ppvar = ["$v0", "$v1", "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$fp", "$t0", "$t1", "$t8"]
        self.inst = {
            "1": ["move", "addiu", "lw", "li", "la"],
            "2": ["sw"],
            "c": ["jalr", "jal"]
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
            },
            "lw_pass_str_tracer": {
                "inst": "lw",
                "operand": {
                    0: {"type": idc.o_reg},
                    1: {"type": idc.o_displ, "check": True, "read": True},
                    2: {"type": idc.o_void}
                }
            },
            "lw_pass_str_li_tracee": {
                "inst": "li",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_imm, "read": True},
                    2: {"type": idc.o_void}
                }
            },
            "lw_pass_str_la_tracee": {
                "inst": "la",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_mem, "read": True},
                    2: {"type": idc.o_void}
                }
            },
            "la_get_func_tracee": {
                "inst": "la",
                "operand": {
                    0: {"type": idc.o_reg, "check": True},
                    1: {"type": idc.o_mem, "read": True},
                    2: {"type": idc.o_void}
                }
            }
        }
        self.tracee_var = []
        self.CmdiModeConfirm = False
        self.CmdiModeConfirmPre = False

    def resetCmdiMode(self):
        self.CmdiMode = True
        self.CmdiModeConfirm = False
        self.CmdiModeConfirmPre = False
        self.tracee_var.pop(-1)

    # def generateStackPpvar(self, start_ea):
    #     func_frame = idc.get_func_attr(start_ea, idc.FUNCATTR_FRAME)
    #     stack_size = idc.get_struc_size(func_frame)
    #     for stk_off in range(0x20, len(stack_size), 4):
    #         self.ppvar.append(f"{stk_off:x}($sp)")
    #     self.ppvar = list(set(self.ppvar))

    def checkOneArg(self, current_ip, start_ea, target_register_idx, check_const) -> (int, bytes):
        # self.generateStackPpvar(start_ea)
        origin_current_ip = current_ip
        current_ip += 4
        local_vars = {
            "last_var": "",
            "curr_var": self.pvar[target_register_idx],
            "data_base": idaapi.get_imagebase(),
            "curr_inst": "",
            "string": "",
            "pred_func": 0,
            "pred_func_name": '',
            "cmdi_mode_res": None,
            "trace_paths": [],
            "orig_ip": 0
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
        # block_list = [(block.start_ea, block.end_ea, block) for block in idaapi.FlowChart(idaapi.get_func(start_ea))]
        # for block in block_list:
        #     if block[0] <= current_ip <= block[1]:
        #         for pred_block in [(pred.start_ea - 4, pred.end_ea-4) for pred in block[2].preds()]:
        #             local_vars["trace_1_stage_paths"].append(
        #                 {"go": block[0], "to": pred_block[1], "end": pred_block[0]})
        #         if len(local_vars["trace_1_stage_paths"]) == 0:
        #             local_vars["trace_paths"].append({"end": block[0]})
        #         break
        local_vars["trace_paths"] = self.genCfgPaths(current_ip, start_ea)
        print(local_vars["trace_paths"])
        if len(local_vars["trace_paths"]) == 0:
            local_vars["trace_paths"].append([(0, 0xffffffff)])
        local_vars["orig_ip"] = current_ip
        local_vars["orig_ag"] = local_vars["last_var"]
        for path in local_vars["trace_paths"]:
            print(path)
            current_ip = local_vars["orig_ip"]
            local_vars["last_var"] = local_vars["orig_ag"]
            while current_ip != start_ea and current_ip != path[0][0] and current_ip-4 != local_vars["orig_ip"]:
                local_vars["curr_inst"] = idc.print_insn_mnem(current_ip)
                print("CURR_INST", local_vars["curr_inst"], self.CmdiMode, hex(origin_current_ip), hex(current_ip))
                if local_vars["curr_inst"] in self.inst["c"] and self.CmdiMode is True and current_ip != origin_current_ip:
                    if local_vars["curr_inst"] == "jalr":
                        check_reg = idc.print_operand(current_ip, 1)
                        print(check_reg)
                        self.ppvar.append(check_reg)
                        upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["la_get_func_tracee"], check_reg)
                        self.ppvar.pop(-1)
                        print("\tGET FUNC BY TRACER")
                        if upwards_inst[0] != -1 and upwards_inst[1] is not None:
                            print("\tTracee is", local_vars["last_var"])
                            self.tracee_var.append(local_vars["last_var"])
                            func_name = idc.get_func_name(upwards_inst[1])
                            if func_name in self.cmdi_pre_func_list:
                                local_vars["pred_func"] = upwards_inst[1]
                                local_vars["pred_func_name"] = func_name
                                self.CmdiMode = False
                                self.CmdiModeConfirmPre = True
                                if local_vars["pred_func_name"] in ["sprintf", "_sprintf", ".sprintf", "strcpy",
                                                                    "_strcpy", ".strcpy", "strncpy", "_strncpy",
                                                                    ".strncpy", "memcpy", "_memcpy", ".memcpy"]:
                                    local_vars["cmdi_mode_res"] = self.checkVaArgs(current_ip, start_ea, start_reg_idx=1)
                                    if self.CmdiModeConfirm is True:
                                        self.resetCmdiMode()
                                        return local_vars["cmdi_mode_res"]
                                elif local_vars["pred_func_name"] in ["snprintf", "_snprintf", ".snprintf"]:
                                    local_vars["cmdi_mode_res"] = self.checkVaArgs(current_ip, start_ea, start_reg_idx=2)
                                    if self.CmdiModeConfirm is True:
                                        self.resetCmdiMode()
                                        return local_vars["cmdi_mode_res"]
                            self.resetCmdiMode()
                    elif local_vars["curr_inst"] == "jal":
                        jal_addr = idc.get_operand_value(current_ip, 0)
                        func_name = idc.get_func_name(jal_addr)
                        if func_name in self.cmdi_pre_func_list:
                            local_vars["pred_func"] = jal_addr
                            local_vars["pred_func_name"] = func_name
                            self.CmdiMode = False
                            self.CmdiModeConfirmPre = True
                            if local_vars["pred_func_name"] in ["sprintf", "_sprintf", ".sprintf", "strcpy", "_strcpy",
                                                                ".strcpy", "strncpy", "_strncpy", ".strncpy", "memcpy",
                                                                "_memcpy", ".memcpy"]:
                                local_vars["cmdi_mode_res"] = self.checkVaArgs(current_ip, start_ea, start_reg_idx=1)
                                if self.CmdiModeConfirm is True:
                                    self.resetCmdiMode()
                                    return local_vars["cmdi_mode_res"]
                            elif local_vars["pred_func_name"] in ["snprintf", "_snprintf", ".snprintf"]:
                                local_vars["cmdi_mode_res"] = self.checkVaArgs(current_ip, start_ea, start_reg_idx=2)
                                if self.CmdiModeConfirm is True:
                                    self.resetCmdiMode()
                                    return local_vars["cmdi_mode_res"]
                        self.resetCmdiMode()
                if local_vars["curr_inst"] in self.inst["1"] and idc.print_operand(current_ip, 0) == local_vars["last_var"]:
                    asm = idc.GetDisasm(current_ip)
                    current_inst = idc.print_insn_mnem(current_ip)
                    operand_1_type = idc.get_operand_type(current_ip, 1)
                    if local_vars["curr_inst"] == "addiu":
                        # LOAD: 0040CDBC          li      $a0, dword_470000
                        # LOAD: 0040CDC0          la      $t9, system
                        # LOAD: 0040CDC4          nop
                        # LOAD: 0040CDC8          jr      $t9; system
                        # LOAD: 0040CDCC          addiu   $a0, (aBinKillall9Ppp - 0x470000)
                        check_inst = self.checkCurrentInst(current_ip, self.instInfo["addiu_pass_str_tracer_1"])
                        print("\tCheck addiu_pass_str_tracer_1", hex(current_ip), check_inst)
                        if check_inst[0] is True and check_inst[1] in self.ppvar+self.pvar and check_inst[2] is not None:
                            upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["addiu_pass_str_li_tracee"], check_inst[1])
                            print("\tUpwards addiu_pass_str_li_tracee", upwards_inst)
                            if upwards_inst[0] != -1 and upwards_inst[1] is not None and idc.print_insn_mnem(upwards_inst[0]-4) not in self.inst["c"]:
                                maybe_str_off = (check_inst[2]+upwards_inst[1])&0xffffffff
                                local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                                return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                        elif check_inst[1] not in self.ppvar+self.pvar and check_inst[1] is not None and check_inst[1] != "$sp":
                            return (0, b'') if check_const is True else (1, b'')
                        # LOAD: 00419FE8          li      $v0, dword_470000
                        # LOAD: 00419FEC          nop
                        # LOAD: 00419FF0          addiu   $s0, $v0, (dword_46B99C - 0x470000)
                        check_inst = self.checkCurrentInst(current_ip, self.instInfo["addiu_pass_str_tracer_2"])
                        print("\tCheck addiu_pass_str_tracer_2", hex(current_ip), check_inst)
                        if check_inst[0] is True and check_inst[1] in self.ppvar+self.pvar and check_inst[2] is not None:
                            upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["addiu_pass_str_li_tracee"], check_inst[1])
                            print("\tUpwards addiu_pass_str_li_tracee", upwards_inst)
                            if upwards_inst[0] != -1 and upwards_inst[1] is not None and idc.print_insn_mnem(upwards_inst[0]-4) not in self.inst["c"]:
                                maybe_str_off = (check_inst[2] + upwards_inst[1]) & 0xffffffff
                                local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                                return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                        elif check_inst[1] not in self.ppvar+self.pvar and check_inst[1] is not None and check_inst[1] != "$sp":
                            return (0, b'') if check_const is True else (1, b'')
                        # .text: 00400A98         lui     $v0, 0x40  # '@'
                        # .text: 00400A9C         addiu   $a0, $v0, (aPlaintextS - 0x400000)
                        if check_inst[0] is True and check_inst[1] in self.ppvar+self.pvar and check_inst[2] is not None:
                            upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["addiu_pass_str_lui_tracee"], check_inst[1])
                            print("\tUpwards addiu_pass_str_lui_tracee", upwards_inst)
                            if upwards_inst[0] != -1 and upwards_inst[1] is not None and idc.print_insn_mnem(upwards_inst[0]-4) not in self.inst["c"]:
                                maybe_str_off = (check_inst[2] + (upwards_inst[1] << 16)) & 0xffffffff
                                local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                                return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                        elif check_inst[1] not in self.ppvar + self.pvar and check_inst[1] is not None and check_inst[1] != "$sp":
                            return (0, b'') if check_const is True else (1, b'')
                        print("Maybe sp tracee")
                        if check_inst[0] is True and check_inst[1] == "$sp" and check_inst[2] is not None:
                            tmp_reg = f"0x{check_inst[2]:X}($sp)"
                            local_vars["last_var"] = tmp_reg
                            if local_vars["last_var"] not in self.ppvar:
                                self.ppvar.append(tmp_reg)
                            print("\tTracee-chg", hex(current_ip), asm)
                            if len(self.tracee_var) != 0 and self.tracee_var[-1] == local_vars["last_var"] and self.CmdiModeConfirmPre is True:
                                self.CmdiModeConfirm = True
                    elif local_vars["curr_inst"] == "lw":
                        check_inst = self.checkCurrentInst(current_ip, self.instInfo["lw_pass_str_tracer"])
                        print("\tCheck lw_pass_str_tracer", hex(current_ip), check_inst)
                        if check_inst[0] is True and check_inst[1] in self.ppvar + self.pvar and check_inst[2] is not None:
                            upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["lw_pass_str_li_tracee"], check_inst[1])
                            print("\tUpwards lw_pass_str_li_tracee", upwards_inst)
                            if upwards_inst[0] != -1 and upwards_inst[1] is not None and idc.print_insn_mnem(upwards_inst[0]-4) not in self.inst["c"]:
                                maybe_str_off = idaapi.get_dword((check_inst[2] + upwards_inst[1]) & 0xffffffff)
                                local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                                return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                        elif check_inst[1] not in self.ppvar + self.pvar and check_inst[1] is not None:
                            return (0, b'') if check_const is True else (1, b'')
                        if check_inst[0] is True and check_inst[1] in self.ppvar + self.pvar and check_inst[2] is not None:
                            upwards_inst = self.traceUpwardsInst(current_ip-4, start_ea, self.instInfo["lw_pass_str_la_tracee"], check_inst[1])
                            print("\tUpwards lw_pass_str_li_tracee", upwards_inst)
                            if upwards_inst[0] != -1 and upwards_inst[1] is not None and idc.print_insn_mnem(upwards_inst[0]-4) not in self.inst["c"]:
                                maybe_str_off = idaapi.get_dword(upwards_inst[1] & 0xffffffff)
                                local_vars["string"] = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                                return (1, local_vars["string"]) if check_const is True else (0, local_vars["string"])
                        elif check_inst[1] not in self.ppvar + self.pvar and check_inst[1] is not None:
                            return (0, b'') if check_const is True else (1, b'')
                    elif idc.print_operand(current_ip, 1) in self.ppvar and idc.get_operand_value(current_ip, 2) == -0x1:
                        local_vars["last_var"] = idc.print_operand(current_ip, 1)
                        print("\tTracee-chg", hex(current_ip), asm)
                        if len(self.tracee_var) != 0 and self.tracee_var[-1] == local_vars["last_var"] and self.CmdiModeConfirmPre is True:
                            print(f"\t[Get Tracee In Cmdi Mode]{self.tracee_var[-1]}")
                            self.CmdiModeConfirm = True
                    elif local_vars["curr_inst"] == "li" and operand_1_type == idc.o_imm:
                        maybe_str_off = idc.get_operand_value(current_ip, 1)
                        s = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                        if s is not None:
                            print("\tget_str", s)
                            return (1, s) if check_const is True else (0, s)
                    # .text: 0041DD90         la      $a1, SOAP_WAN_PPPCONNECTION
                    # .text: 0041DD94         la      $a2, CPRequest
                    # .text: 0041DD98         la      $a0, SOAP_body  # s
                    # .text: 0041DD9C         jalr    $t9; sprintf
                    elif local_vars["curr_inst"] == "la" and operand_1_type == idc.o_mem:
                        maybe_str_off = idc.get_operand_value(current_ip, 1)
                        s = idc.get_strlit_contents(maybe_str_off, -1, idc.STRTYPE_C)
                        if s is not None:
                            print("\tget_str", s)
                            return (1, s) if check_const is True else (0, s)
                    # else:
                    #     return (0, b'') if check_const is True else (1, b'')
                if len(path) != 1:
                    for block_idx in range(len(path)):
                        if path[block_idx][0] == current_ip and block_idx != 0:
                            current_ip = path[block_idx-1][1]
                current_ip = idc.prev_head(current_ip)
        return 0, b''

    def checkVaArgs(self, current_ip, start_ea, start_reg_idx=0):
        local_vars = {
            "cntFmt": 0,
            "filling": '',
        }
        if self.CmdiMode is False and self.CmdiModeConfirmPre is True:
            print("arg 0 start")
            self.checkOneArg(current_ip, start_ea, 0, True)
            print("arg 0 end")
            self.CmdiModeConfirmPre = False
        firstArg = self.checkOneArg(current_ip, start_ea, start_reg_idx, True)
        print(firstArg)
        if firstArg[0] == 1 and firstArg[1] is not None and len(firstArg[1]) != 0:
            fmt_str = firstArg[1].decode("latin-1")
            if fmt_str.find("%") == -1:
                return 1, fmt_str.encode("latin-1")
            print("\tFMT STR:", fmt_str)
            for i in range(1, 7):
                try:
                    testor = tuple([0] * i)
                    s = fmt_str % testor
                    local_vars["cntFmt"] = i
                    break
                except Exception as e:
                    continue
        else:
            return 0, b''
        filling = []
        for var_idx in range(local_vars["cntFmt"]):
            print(f"====================={str(var_idx + 1)}========================")
            if self.isStrFmtIdx(firstArg[1], var_idx) is True:
                curr_var = self.checkOneArg(current_ip, start_ea, var_idx + start_reg_idx + 1, True)
                if curr_var[0] == 0:
                    return 0, b''
                if curr_var[1] is None:
                    filling.append("[UNKNOWN]")
                else:
                    filling.append(curr_var[1].decode("latin-1"))
        try:
            local_vars["filling"] = fmt_str % tuple(filling)
        except Exception as e:
            print(str(Exception), str(e))
            return 1, b''
        return 1, local_vars["filling"].encode("latin-1")


if __name__ == "__main__":
    functions = {}
    scanner = VulnScanner()
    for ea in Functions():
        functions[idc.get_func_name(ea)] = ea
    for check_point in scanner.check_list:
        vulnFunction = check_point["function"]
        if scanner.arch == "amd64" and vulnFunction.startswith("_"):
            vulnFunction = "." + vulnFunction[1:]
        if vulnFunction in functions.keys():
            CmdiSwitch = vulnFunction in ["system", "_system", "popen", "_popen"]
            if scanner.arch == "mips":
                mipsVulnScanner = MipsVulnScanner(CmdiMode=CmdiSwitch)
                mipsVulnScanner.checkVuln(functions[vulnFunction], check_point)
            elif scanner.arch == "arm":
                armVulnScanner = ArmVulnScanner(CmdiMode=CmdiSwitch)
                armVulnScanner.checkVuln(functions[vulnFunction], check_point)
            elif scanner.arch == "amd64":
                x64VulnScanner = X64VulnScanner(CmdiMode=CmdiSwitch)
                x64VulnScanner.checkVuln(functions[vulnFunction], check_point)
    output.close()
    idc.qexit(0)

