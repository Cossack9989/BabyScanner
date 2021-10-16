import os
import glob
import subprocess


data_set = glob.glob('D:\\Project\\PythonProject\\datacon2021\\data_set\\*')
ida_path = "C:\\Users\\bytedance\\SecTool\\IDA\\IDA Pro 7.5 SP3\\ida.exe"
ida64_path = "C:\\Users\\bytedance\\SecTool\\IDA\\IDA Pro 7.5 SP3\\ida64.exe"
script_path = "D:\\Project\\PythonProject\\datacon2021\\VulnScanner.py"
# script_path = "D:\\Project\\PythonProject\\datacon2021\\scanner-IoT.py"

for file_path in data_set:
    print(file_path)
    if file_path.endswith('80'):
        exe = ida64_path
    else:
        exe = ida_path
    command = [exe, "-A", "-b0", f"-S{script_path}", "-Lida.log", file_path]
    p = subprocess.Popen(command)
    p.wait()


fl = os.listdir("./data_set/")
for fb in fl:
    if fb.find(".") != -1:
        os.remove(f"./data_set/{fb}")
