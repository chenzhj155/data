
import idaapi, idc, idautils
import ida_bytes
import ida_name



enc_strings = 0x40B930
bytes_arr = 0x410120



def set_hexrays_comment(comment, address):
    cfunc = idaapi.decompile(address)
    eamap = cfunc.get_eamap()
    decompObjAddr = eamap[address][0].ea
    tl = idaapi.treeloc_t()
    tl.ea = decompObjAddr
    commentSet = False
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.itp = itp
        cfunc.set_user_cmt(tl, comment)
        cfunc.save_user_cmts()
        #apparently you have to cast cfunc to a string, to make it update itself
        unused = cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            commentSet = True
            cfunc.save_user_cmts()
            break
        cfunc.del_orphan_cmts()

        if not commentSet:
            print("[ERROR] Please set \"%s\" to line %s manually" % (comment, hex(int(address))))




def set_comment(address, text):
    ## Set in dissassembly
    idc.set_cmt(address, text,0)
    ## Set in decompiled data
    set_hexrays_comment(text, address)


def decrypt_string(idx):
    if idx >= 0x36F4:
        return    # out of bounds
    res = ""
    while True:
        c = idc.get_wide_byte(enc_strings+idx) ^ idc.get_wide_byte(bytes_arr + (idx&0x3F))
        if c == 0: break
        res += chr(c)
        idx += 1
    return res

def get_xref_list(fn_addr):

    return [addr.frm for addr in idautils.XrefsTo(fn_addr)]



error_funs={
0x401827:[0x309d],
0x403726:[0x5D4,0x238,0x2C4,0x1D5E,0x5EE,0x26A1,0x32C1, 0x20F5,0x3517,0x22DF,0x2854,0x2557, 0x1F2, 0x1DE5,0x3662],
0x4037d4:[0xD9B,0x26FC,0x220,0x193A,0x68,0x26C5, 0x1A,0xC05,0x2EAA],
0x403b51:[0x557],
0x403c95:[0x26B6,0x34DE],
0x403d8e:[0x21AE,0x20E0,0x864],
0x40434b:[0x60],
0x4054d5:[0x2587,0x2ff0,0x291b,0x35d7,0x2429,0x28a8,0x4b6,0xf44,0x2176,0x232b,0x18d8,0x3202,0x2168,0x2a2c,0x20b],
0x4059b9:[0xc44],


0x406688:[0x29E1],
0x4068c9:[0x8A4,0x28E9,0x1CFE,0x245A],
0x4077b4:[0x25CC]

}


def decode_strs():
    funcs = get_xref_list(0x4065B7)

    for x in funcs:




        ea = idc.prev_head(x)
        t = idc.get_operand_type(ea, 1)
        # 有些不满足 手动设置
        if t == idc.o_imm:


            idx = idc.get_operand_value(ea, 1)
            dec = decrypt_string(idx)
            # 方便程序漏洞可以手动添加
            print(dec)
            y = x
            set_comment(x, dec)

        else:
            if(x in error_funs.keys() ):
                print(hex(x))
                restr=''
                for num in error_funs[x]:
                    dec = decrypt_string(num)
                    restr=dec+'\n'+restr
                restr=restr.strip('\n')
                print(restr)
                set_comment(x,restr)







def api():


    funcs = get_xref_list(0x40599D)
    for ea in funcs:
        ea= idc.prev_head(ea)
        idx = idc.get_operand_value(ea, 0)
        while(1):
            dwData=ida_bytes.get_dword(idx)

            if(dwData==0 or dwData==0xffffffff):
                break
            if (type(dwData) == None):
                break


            func_num=ida_bytes.get_dword(idx+4)
            funcsss=decrypt_string(func_num)



            print(funcsss)
            print(hex(dwData))
            idc.set_name(dwData,funcsss,ida_name.SN_FORCE)

            idx = idx + 12




decode_strs()
api()
