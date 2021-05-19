from config import *
import cfgview_helper
import r2pipe
import json

def get_cfgjson(r, func):
    """
        return bb as json format
    """
    r2_command = "pdbj @ `addr`"
    bb_list = filter(cfgview_helper.is_not_blank, cfgview_helper.get_bblist(r, func))
    parsed_line = {}
    parsed_bbjson = ""
    block_idx = 0
    for addr in bb_list:
        bb_json = r.cmd(r2_command.replace("`addr`", addr))
        bb_json = json.loads(bb_json)
        for line in bb_json:
            parsed_line['offset'] = hex(line['offset'])
            parsed_line['disasm'] = line['disasm']
            parsed_line['block_idx'] = block_idx  
            parsed_bbjson += json.dumps(parsed_line)
        block_idx += 1
            
    return parsed_bbjson