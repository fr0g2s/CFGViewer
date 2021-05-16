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
    width = []
    bb_list = filter(is_not_blank, get_bblist(r, func))   # get start address of bb
    count = 0
    for addr in bb_list:
        bb = get_bb(r, addr)
        # list에 dict 자료를 추가하면 이전에 있던 내용이 새로 추가될 데이터로 바뀜. 덮어 써지는건지 모르겠음.
        #separated_bblist = get_separatedbblist(bb)  # {addr| bincode| opcode| operand}
        #orginized_bb = get_orginizedbb(separated_bblist)    # "addr bincode opcode operand"
        parsed_bb, max_len = get_parsedbb(bb)
        cfg.append({'idx':count, 'content':parsed_bb})
        width.append(max_len)
        count += 1
    return cfg, width

def get_parsedbb(bb):
    """
        "addr bincode opcode operand\\n" 문자열을 리턴한다
    """
    if HELPER_DEBUG:
        print('[debug] get_parsedbb')
    parsed_bb = ""
    max_len = -1
    for line in filter(is_not_blank, ''.join(bb).split('\r\n')):
        line = line.split()
        st_idx = get_startidx(line)    # 주소가 시작하는 인덱스 
        if st_idx == -1:    # 해당 라인은 0x"주소" 형태의 필드가 없음. 디스어셈블 내용이 없음.
            continue
        opcode = ' '.join(line[4:])
        opcode_end = opcode.find(';')
        if opcode_end == -1:
            opcode_end = None
        parsed_line = "{0} | {1} {2} {3}".format(line[st_idx], line[st_idx+1], line[st_idx+2], opcode[st_idx+2:opcode_end]) + "\r\n"    # 기계어 추가하면 공백이 안맞음. 
        parsed_bb += parsed_line

        if max_len < len(parsed_line):
            max_len = len(parsed_line)
    return parsed_bb, max_len

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
    print(filepath)
    r.cmd('aaa')
    return r
    
def get_startidx(l):
    if HELPER_DEBUG:
        print('[debug] get_startidx')
    for e in l:
        if e.startswith('0x'):
            if l.index(e) != len(l)-1:
                return l.index(e)
        if e.startswith(';'):   # 0x가 나오기 전에 ;가 나오면 코드가 아니다.
            return -1
    return -1

def get_bblist(r, func):
    r2_command = 'afb @ `func`'
    f"""
        r.cmd(%s)
        get start address of bb
    """ % r2_command
    
    if HELPER_DEBUG:
        print('[debug] get_bblist')
    bb_list = []
    bb_infolist = r.cmd(r2_command.replace('`func`', func)).split('\r\n')
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
    r2_command = 'pdb @ `addr`'
    f"""
        r.cmd(%s)
    """ % r2_command
    
    if HELPER_DEBUG:
        print('[debug] get_cfg')
    bb = r.cmd(r2_command.replace("`addr`",addr))
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
        print('append ', separated_bb)
        separated_bblist.append(separated_bb)
        print('appended', separated_bblist)
        
    return separated_bblist

def get_orginizedbb(separated_bblist):
    orginized_bb = ""
    for e in separated_bblist:
        line = "{0} | {1} \t {2} {3} \r\n".format(e['addr'], ' '.join(e['bincode']), e['opcode'], e['operand'])
        orginized_bb += line
    return orginized_bb
