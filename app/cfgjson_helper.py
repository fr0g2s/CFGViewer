from config import *
import r2pipe
import os

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