from config import *
import os
import r2pipe
import time

def get_filelist():
    filelist = os.listdir(Config.UPLOAD_DIR+"\\")
    return filelist

def getFileType(filename):
    """
        specifiy file type via file signature
    """
    filetype = None
    with open(filename, 'rb') as f:
        sign = f.read(4)
        
        if b"\x4D\x5A" in sign:
            filetype = "pe"
        elif b"\x7f\x45\x4C\x46" in sign:
            filetype = "elf"
    return filetype

def get_r2pipe(filename):
    """
        r = r2pipe.open(filepath)
        r.cmd('aaa')
        return r
    """
    filepath = os.path.join(Config.UPLOAD_DIR, filename)
    r = r2pipe.open(filepath)
    r.cmd('aaa')
    return r

def get_cfg(r, func):
    """
        r.cmd('pdf @main')
    """
    cfg = r.cmd('pdf @'+func)
    return cfg


def get_funcdict(r):
    """
        return function information as dictionary.
        [addr : symbol]
    """
    print('[debug] get_funclist')
    allfunclist = r.cmd('afl').split("\r\n")
    funcdict = {}
    for line in allfunclist:
        if "sym" in line:
            if "imp" in line:   # 라이브러리 함수는 안본다.
                continue
            func_name = line[line.index('sym'):]
        elif "main" in line:
            if line[line.index('main')-1] != ' ':   # d_main 이라던가.. 내가 모르는게 나올 수도? 이건 안봄
                continue
            func_name = line[line.index('main'):]
        else:   # 그 외의 경우는 표시하지 않는다. 이 경우까지 봐야할 정보면 기드라를 써라!
            continue
        addr = line[line.index('0x'):line.index(' ')]
        funcdict[addr] = func_name
            
    return funcdict
    