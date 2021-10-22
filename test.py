# s = open("75_2", "r").read().strip()
# pos = 0
# last_off = 0
# while True:
#     si = s.find(".~", pos)
#     if si == -1:
#         break
#     print(s[si:si+4], si, si-last_off)
#     pos = si + 4
#     last_off = si
# from base64 import b64decode as bd
# s = s.replace(".~..", "").replace(".~.$", "").replace(".~.}", "").replace(".~.(", "").replace(".~.l", "").replace(".~.j", "")
# d = {a:s.count(a) for a in set(s)}
# for k in d.keys():
#     print(k, d[k])
# open("75.1.1", "wb").write(s.encode())
# s = open("36", "r").read().strip()
import csv
from base64 import b64decode as bd
# open("data_set/36", "wb").write(bd(s.encode()))

# s1 = open("75.1.1", "rb").read()
# s2 = open("data_set/75", "rb").read(len(s1))
# print(s1 == s2)

# import os
# fl = os.listdir("./data_set/")
# for fb in fl:
#     if fb.find(".") != -1:
#         os.remove(f"./data_set/{fb}")
# # import os
#
# fl = os.listdir("./data_set/")
# for fb in fl:
#     os.rename(f"./data_set/{fb}", f"./data_set/{fb}".replace("_r", ""))
    # nu = int(fb)
    # if nu < 10:
    #     os.rename(f"./data_set/{fb}", f"./data_set/{str(nu*10)}_r")
    # elif nu >=10 and nu %10 != 9:
    #     os.rename(f"./data_set/{fb}", f"./data_set/{str(nu+1)}_r")
    # elif nu >=10 and nu %10 == 9:
    #     os.rename(f"./data_set/{fb}", f"./data_set/{str(int((nu+1)/10))}_r")

# f = open("res_1015.txt", "r")
# s = f.read()
# l = s.split('\n')
# t = ''
# for line in l:
#     if line.startswith("48,"):
#         line += "HACK"
#         line = line.replace("0HACK", "1")
#     t += line + '\n'
# print(t)
# open("res_1015_final.txt", "w").write(t)
#
# s = s.replace(',', ', ')
# open("res1014_final_fixed2.txt", "w").write(s)
#
# buf = ''
# for i in range(46):
#     tmp = open(f"21.{str(i)}.txt", "r").read()
#     buf += tmp
# open("data_set/21", "wb").write(bd(buf.encode()))
# print(open("res_1016_final2.txt","r").read().find("\n\n"))

# check_cnt_dict = [
#     {"61": {"system": 10, "sprintf": 61}},
#     {"95": {"system": 3, "sprintf": 24, "snprintf": 23}},
#     {"59": {"system": 41, "popen": 4, "sprintf": 92, "snprintf": 21, "AES_set_encrypt_key": 1, "EVP_DecryptInit_ex": 1, "AES_cbc_encrypt": 1}},
#     {"92": {"sprintf": 7, "snprintf": 4}},
#     {"66": {"system": 45, "popen": 4, "sprintf": 41, "snprintf": 13}},
#     {"50": {"AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1}},
#     {"68": {"system": 1, "popen": 1, "sprintf": 13, "snprintf": 11}},
#     {"57": {"AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1}},
#     {"32": {"system": 12, "popen": 1, "sprintf": 47, "snprintf": 35}},
#     {"35": {"sprintf": 1, "AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1}},
#     {"69": {"system": 8, "popen": 9, "sprintf": 212}},
#     {"56": {"system": 12, "sprintf": 45}},
#     {"51": {"sprintf": 17, "snprintf": 2}},
#     {"58": {"system": 52, "sprintf": 97, "snprintf": 1}},
#     {"67": {"system": 5, "sprintf": 35, "snprintf": 3}},
#     {"93": {"system": 5, "popen": 1, "sprintf": 7, "snprintf": 4}},
#     {"94": {"system": 1, "sprintf": 14}},
#     {"60": {"system": 164, "sprintf": 384, "snprintf": 120, "COMMAND": 160}},
#     {"34": {"system": 401, "sprintf": 548, "snprintf": 1110}},
#     {"33": {"system": 63, "popen": 2, "sprintf": 155, "snprintf": 8, "COMMAND": 105}},
#     {"20": {"AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1}},
#     {"18": {"system": 3, "popen": 2, "sprintf": 775, "snprintf": 90, "doSystemCmd": 181}},
#     {"27": {"system": 33, "popen": 1, "sprintf": 32, "snprintf": 12, "AES_cbc_encrypt": 3}},
#     {"9": {"system": 149, "popen": 26, "sprintf": 330, "snprintf": 94, "EVP_DecryptInit_ex": 1, "EVP_EncryptInit_ex": 1}},
#     {"11": {"system": 5, "popen": 1, "sprintf": 1, "snprintf": 4}},
#     {"7": {"system": 21, "popen": 1, "sprintf": 37, "snprintf": 1}},
#     {"29": {"system": 80, "popen": 3, "sprintf": 62, "snprintf": 3}},
#     {"16": {"AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1}},
#     {"42": {"system": 53, "popen": 6, "sprintf": 169, "snprintf": 2}},
#     {"89": {"AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1}},
#     {"45": {"system": 7, "popen": 1, "sprintf": 2, "snprintf": 3}},
#     {"73": {"sprintf": 6}},
#     {"87": {"system": 3, "popen": 1, "sprintf": 27}},
#     {"80": {"system": 19, "popen": 8, "sprintf": 39, "snprintf": 24}},
#     {"74": {"system": 6, "popen": 6, "sprintf": 56, "snprintf": 5}},
#     {"6": {"system": 11, "sprintf": 41}},
#     {"28": {"system": 6, "sprintf": 14, "snprintf": 1}},
#     {"17": {"sprintf": 6, "snprintf": 47}},
#     {"1": {"popen": 1, "sprintf": 64, "snprintf": 4}},
#     {"10": {"system": 80, "popen": 3, "sprintf": 45, "snprintf": 359}},
#     {"19": {"system": 8, "sprintf": 13, "snprintf": 32}},
#     {"26": {"AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 2}},
#     {"8": {"system": 12, "popen": 1, "sprintf": 52, "snprintf": 19}},
#     {"21": {"system": 111, "popen": 9, "sprintf": 1164, "snprintf": 261, "AES_set_encrypt_key": 3, "AES_set_decrypt_key": 2, "AES_cbc_encrypt": 4}},
#     {"75": {"system": 15, "popen": 8, "sprintf": 389, "snprintf": 1677, "EVP_DecryptInit_ex": 1, "EVP_EncryptInit_ex": 2}},
#     {"86": {"popen": 5, "sprintf": 11, "snprintf": 10}},
#     {"72": {"system": 53, "popen": 2, "sprintf": 31, "snprintf": 111}},
#     {"44": {"system": 2, "popen": 1, "sprintf": 4, "snprintf": 12}},
#     {"43": {"system": 95, "popen": 4, "sprintf": 75, "snprintf": 158}},
#     {"88": {"system": 1, "snprintf": 1}},
#     {"38": {"popen": 1, "snprintf": 4, "AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 2}},
#     {"36": {"system": 3, "popen": 2, "sprintf": 784, "snprintf": 90, "doSystemCmd": 181}},
#     {"31": {"AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1}},
#     {"91": {"system": 573, "popen": 3, "sprintf": 1310, "snprintf": 190, "AES_set_encrypt_key": 2, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 2}},
#     {"65": {"system": 1, "sprintf": 12}},
#     {"62": {"system": 13, "popen": 2, "sprintf": 64, "snprintf": 15}},
#     {"96": {"system": 36, "sprintf": 139, "snprintf": 8}},
#     {"100": {"system": 16, "popen": 2, "sprintf": 26, "snprintf": 2, "DES_set_key_checked": 3}},
#     {"54": {"system": 41, "popen": 3, "sprintf": 198, "snprintf": 14}},
#     {"98": {"system": 6, "popen": 1, "sprintf": 6, "snprintf": 5}},
#     {"53": {"system": 18, "sprintf": 59, "snprintf": 16}},
#     {"30": {"system": 18, "popen": 1, "sprintf": 51, "snprintf": 53}},
#     {"37": {"system": 2}},
#     {"39": {"system": 1, "sprintf": 11}},
#     {"99": {"system": 1, "popen": 2, "sprintf": 1, "snprintf": 1}},
#     {"52": {"sprintf": 1, "snprintf": 5}},
#     {"55": {"system": 399, "popen": 4, "sprintf": 602, "snprintf": 67}},
#     {"97": {"system": 14, "sprintf": 42, "snprintf": 2}},
#     {"63": {"system": 34, "sprintf": 75, "snprintf": 29}},
#     {"64": {"AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1}},
#     {"90": {"snprintf": 8}},
#     {"46": {"system": 70, "sprintf": 93, "snprintf": 18}},
#     {"79": {"system": 9, "sprintf": 26, "snprintf": 1}},
#     {"41": {"system": 2, "sprintf": 1, "snprintf": 52}},
#     {"83": {"AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1}},
#     {"77": {"system": 342, "popen": 91, "sprintf": 1331, "snprintf": 16, "_system": 30}},
#     {"48": {"system": 107, "popen": 4, "sprintf": 425, "snprintf": 6, "COMMAND": 32}},
#     {"70": {"system": 295, "popen": 6, "sprintf": 276, "snprintf": 236, "EVP_DecryptInit_ex": 2, "EVP_EncryptInit_ex": 2}},
#     {"84": {"system": 77, "popen": 8, "sprintf": 111, "snprintf": 27}},
#     {"24": {"system": 46, "popen": 5, "sprintf": 849, "snprintf": 8, "_system": 69}},
#     {"23": {}},
#     {"4": {"system": 20, "sprintf": 27, "snprintf": 26}},
#     {"15": {"popen": 1}},
#     {"3": {}},
#     {"12": {"system": 8, "sprintf": 23, "snprintf": 2}},
#     {"85": {"system": 24, "popen": 8, "sprintf": 56, "snprintf": 69, "AES_set_encrypt_key": 1, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 3}},
#     {"71": {"system": 76, "sprintf": 75}},
#     {"76": {"system": 4, "popen": 1, "sprintf": 637, "snprintf": 35, "doSystemCmd": 149}},
#     {"82": {"sprintf": 99}},
#     {"49": {"popen": 1, "sprintf": 10, "snprintf": 50}},
#     {"40": {"system": 520, "popen": 19, "sprintf": 505, "snprintf": 828, "AES_set_decrypt_key": 1, "AES_cbc_encrypt": 1, "doSystem": 13}},
#     {"47": {"system": 5, "sprintf": 8, "snprintf": 126}},
#     {"78": {"system": 26, "sprintf": 9, "snprintf": 10}},
#     {"2": {}},
#     {"13": {"system": 5, "popen": 1, "sprintf": 7, "snprintf": 3}},
#     {"5": {"system": 216, "popen": 52, "sprintf": 377, "snprintf": 146, "doSystem": 349}},
#     {"14": {"system": 21, "popen": 8, "sprintf": 71, "snprintf": 19}},
#     {"22": {"system": 38, "popen": 31, "sprintf": 78, "snprintf": 177, "doSystem": 392, "doSystembk": 17}},
#     {"25": {"system": 86, "popen": 3, "sprintf": 351, "snprintf": 19}}
# ]

check_list = {}
data = open("res_1020_final.txt", "r").read().split('\n')
for line in data:
    fidx = line.split(',')
    if len(fidx) == 4:
        if fidx[0] not in check_list.keys():
            check_list[fidx[0]] = {}
        if fidx[1] not in check_list[fidx[0]].keys():
            check_list[fidx[0]][fidx[1]] = {
                "1": 0,
                "0": 0,
            }
        check_list[fidx[0]][fidx[1]][fidx[3]] += 1

csv_fd = csv.writer(open("analysis1021.csv", "w", newline=''))
csv_fd.writerow(["file id", "func name", "1 cnt", "0 cnt"])
for fid in check_list.keys():
    for fn in check_list[fid].keys():
        csv_fd.writerow([fid, fn, check_list[fid][fn]["1"], check_list[fid][fn]["0"]])

#
# for record in check_cnt_dict:
#
#
# for fid in check_list.keys():
#     for fn in check_list[fid].keys():
#         if check_list[fid][fn]["1"] + check_list[fid][fn]["0"] != check_cnt_dict[fid][fn]:
#             print(fid, fn, check_cnt_dict[fid][fn], check_list[fid][fn]["1"] + check_list[fid][fn]["0"])