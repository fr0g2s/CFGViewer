import os

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