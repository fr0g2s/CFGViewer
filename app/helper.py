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

def get_cfg(filename):  # full path
    filepath = os.path.join(Config.UPLOAD_DIR, filename)
    r = r2pipe.open(filepath)
    r.cmd('aaa')
    cfg = r.cmd('pdf @main')
    print(r.cmd('VV'))

    return cfg