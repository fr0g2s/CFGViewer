from flask import url_for
from config import *
import os
import r2pipe
import time

def get_filelist():
    if HELPER_DEBUG:
        print('[debug] get_filelist')
    filelist = os.listdir(Config.UPLOAD_DIR+"\\")
    return filelist

def get_filetype(filename):
    """
        specifiy file type via file signature
    """
    if HELPER_DEBUG:
        print('[debug] get_filetype')
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
    if HELPER_DEBUG:
        print('[debug] get_r2pipe')
    filepath = os.path.join(Config.UPLOAD_DIR, filename)
    r = r2pipe.open(filepath)
    r.cmd('aaa')
    return r

def get_cfg(r, func):
    """
        get bb list
    """
    if HELPER_DEBUG:
        print('[debug] get_cfg')
    cfg = []

    bb_list = get_bblist(r, func)   # get start address of bb
    for addr in bb_list:
        if addr is '':
            continue
        cfg.append(get_bb(r, addr))
    return cfg

def get_bblist(r, func):
    command = 'afb @ `func`'
    f"""
        r.cmd(%s)
        get start address of bb
    """ % command
    
    if HELPER_DEBUG:
        print('[debug] get_bblist')
    bb_list = []
    bb_infolist = r.cmd(command.replace('`func`', func)).split('\r\n')
    for bb_info in bb_infolist:
        bb_info = bb_info.split(' ')
        try:
            start = bb_info[0]
            end = bb_info[2]
            # for future
            true = bb_info[5]
            false = bb_info[7]
        except IndexError:  # if no true/false branch
            true = None
            false = None
        bb_list.append(start)
    return bb_list

def get_bb(r, addr):
    command = 'pdb @ `addr`'
    f"""
        r.cmd(%s)
    """ % command
    
    if HELPER_DEBUG:
        print('[debug] get_cfg')
    bb = r.cmd(command.replace("`addr`",addr))
    return bb


def get_funcdict(r):
    """
        return function information as dictionary.
        [addr : symbol]
    """
    if HELPER_DEBUG:
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


def get_separatedcfg(cfg):
    """
    디스어셈블한 내용을 "주소|기계어|opcode|operand" 포맷으로 나눈다.
    """
    if HELPER_DEBUG:
        print('[debug] get_separatedcfg')
    class formatted_cfg:
        addr = ""
        bincode = ""
        opcode = ""
        operand = ""
    
    new_cfg = []
    
    return cfg