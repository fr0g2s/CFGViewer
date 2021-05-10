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

def is_not_blank(s):
    return True if s != '' else False

def get_cfg(r, func):
    """
        bb list -> separated bb list -> cfg
        return cfg
    """
    if HELPER_DEBUG:
        print('[debug] get_cfg')
    cfg = []

    bb_list = filter(is_not_blank, get_bblist(r, func))   # get start address of bb
    for addr in bb_list:
        bb = get_bb(r, addr)
        separated_bblist = get_separatedbblist(bb)
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


def get_separatedbblist(bb):
    """
    bb를 "addr|bincode|opcode|operand" 포맷으로 나눈다.
    ['addr'] = 코드 주소
    ['bincode'] = 기계어
    ['opcode'] = 연산자
    ['operand'] = 피연산자
    """
    if HELPER_DEBUG:
        print('[debug] get_separatedcfg')
    
    separated_bblist = []    
    separated_bb = {}
    for line in filter(is_not_blank, ''.join(bb).split('\r\n')):
        line = line.split()
        if not line[1].startswith('0x'):
            continue
        separated_bb['addr'] = line[1]
        separated_bb['bincode'] = line[2]
        separated_bb['opcode'] = line[3]
        separated_bb['operand'] = ' '.join(line[4:])
        print(separated_bb)
        separated_bblist.append(separated_bb)
        
    return separated_bblist