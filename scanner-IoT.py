from idc import *
from idaapi import *
from idautils import *


from pwn import *
idc.auto_wait()
output = open("D:\\Project\\PythonProject\\datacon2021\\res2.txt", "a+")

ci_functions = [
    "popen",
    "system",
    "doSystemCmd",
    "doSystembk",
    "doSystem",
    "COMMAND",
    "_popen",
    "_system",
    "_doSystemCmd",
    "_doSystembk",
    "_doSystem",
    "_COMMAND"
]
fb_functions = [
    "sprintf",
    "snprintf",
    "_sprintf",
    "_snprintf"
]
cw_functions = [
    # "AES_set_encrypt_key",
    # "AES_set_decrypt_key",
    # "EVP_DecryptInit_ex",
    # "EVP_EncryptInit_ex",
    "DES_set_key_checked",
    "AES_cbc_encrypt",
    # "_AES_set_encrypt_key",
    # "_AES_set_decrypt_key",
    # "_EVP_DecryptInit_ex",
    # "_EVP_EncryptInit_ex",
    "_DES_set_key_checked",
    "_AES_cbc_encrypt",
]


class Tracer(object):

    def __init__(self, function, path):
        self.func = function
        self.path = path

    def trace(self):
        if self.func in ["popen", "_popen", "system", "_system"]:
            return 1
        elif self.func in ["AES_set_encrypt_key", "_AES_set_encrypt_key", "AES_set_decrypt_key", "_AES_set_decrypt_key"]:
            return 0
        elif self.func in ["sprintf", "snprintf", "_sprintf", "_snprintf"]:
            return 1
        elif self.func in ["doSystembk", "_doSystembk", "doSystem", "_doSystem"]:
            return 0


class Scanner(object):

    def __init__(self):
        self.tag = "default"
        self.entry = []
        self.func_name_list = []
        self.basic_threat_func_list = {
            "ci": [],
            "cw": [],
            "fb": []
        }
        self.accessible_threat_func_list = {
            "ci": {},
            "cw": {},
            "fb": {}
        }

    def FirstScan(self):
        # info("Scanning 1 round")
        func_list = Functions()
        self.func_name_list = [get_func_name(func) for func in func_list]
        # for ci_function in ci_functions:
        #     if ci_function in self.func_name_list:
        #         self.basic_threat_func_list["ci"].append(ci_function)
        # info("\tThreat in Command injection: {}".format(str(self.basic_threat_func_list["ci"])))
        for cw_function in cw_functions:
            if cw_function in self.func_name_list:
                self.basic_threat_func_list["cw"].append(cw_function)
        info("\tThreat in Crypto misuse: {}".format(str(self.basic_threat_func_list["cw"])))
        # for func in self.basic_threat_func_list["cw"]:
        #     for addr in Functions():
        #         if get_func_name(addr) == func:
        #             code_xrefs = CodeRefsTo(addr, False)
        #             for code_xref in code_xrefs:
        #                 info(f'{get_root_filename()},{func},{hex(code_xref)},0\n')
                        # output.write(f'{get_root_filename()},{func},{hex(code_xref)},0\n')
        # for fb_function in fb_functions:
        #     if fb_function in self.func_name_list:
        #         self.basic_threat_func_list["fb"].append(fb_function)
        # info("\tThreat in Format String Bug: {}".format(str(self.basic_threat_func_list["fb"])))
        # TODO 使用框架特性，如GoAhead或其他存在跳转调用的，及时更新 SELF.ENTRY

    def SecondScan(self):
        def NameFunc(paths):
            retList = []
            for path in paths:
                retList.append([get_func_name(addr) for addr in path])
            return retList
        info("Scanning 2 round")
        if self.tag is "default":
            self.entry.append(get_name_ea_simple('main'))
        for entry in self.entry:
            for ci_function in self.basic_threat_func_list["ci"]:
                try:
                    ci_tmp_threat = AlleyCatFunctionPaths(entry, get_name_ea_simple(ci_function)).paths
                    assert ci_tmp_threat != [[]]
                except Exception as e:
                    warning(f"no {ci_function} call-chain")
                    continue
                if ci_function not in self.accessible_threat_func_list["ci"].keys():
                    self.accessible_threat_func_list["ci"][ci_function] = [NameFunc(ci_tmp_threat)]
                else:
                    self.accessible_threat_func_list["ci"][ci_function].append(NameFunc(ci_tmp_threat))
            for cw_function in self.basic_threat_func_list["cw"]:
                try:
                    cw_tmp_threat = AlleyCatFunctionPaths(entry, get_name_ea_simple(cw_function)).paths
                    assert cw_tmp_threat != [[]]
                except Exception as e:
                    warning(f"no {cw_function} call-chain")
                    continue
                if cw_function not in self.accessible_threat_func_list["cw"].keys():
                    self.accessible_threat_func_list["cw"][cw_function] = [NameFunc(cw_tmp_threat)]
                else:
                    self.accessible_threat_func_list["cw"][cw_function].append(NameFunc(cw_tmp_threat))
            for fb_function in self.basic_threat_func_list["fb"]:
                try:
                    fb_tmp_threat = AlleyCatFunctionPaths(entry, get_name_ea_simple(fb_function)).paths
                    assert fb_tmp_threat != [[]]
                except Exception as e:
                    warning(f"no {fb_function} call-chain")
                    continue
                if fb_function not in self.accessible_threat_func_list["fb"].keys():
                    self.accessible_threat_func_list["fb"][fb_function] = [NameFunc(fb_tmp_threat)]
                else:
                    self.accessible_threat_func_list["fb"][fb_function].append(NameFunc(fb_tmp_threat))
        # info("\tThreat in Command injection: {}".format(str(self.accessible_threat_func_list["ci"])))
        # info("\tThreat in Crypto misuse: {}".format(str(self.accessible_threat_func_list["cw"])))
        # info("\tThreat in Format String Bug: {}".format(str(self.accessible_threat_func_list["fb"])))

    def ThirdScan(self):
        info("Scanning 3 round")
        for ci_threat in self.accessible_threat_func_list["ci"].keys():
            for path in self.accessible_threat_func_list["ci"][ci_threat]:
                Tracer(ci_threat, path)

    def scan(self):
        self.FirstScan()
        self.SecondScan()


Scanner().FirstScan()
output.close()
idc.qexit(0)

func = "AES_cbc_encrypt"
for addr in Functions():
    if get_func_name(addr) == func:
        code_xrefs = CodeRefsTo(addr, False)
        for code_xref in code_xrefs:
            info(f'{get_root_filename()},{func},{hex(code_xref)},0\n')