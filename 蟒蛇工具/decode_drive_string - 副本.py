
import idc
import idautils
import idaapi



key='%{vwG+KL-DEF.012!3OS)T_4qrH&IJ789;@ABCm`MN/Un}V5st#ux6p,WX(YZ[]^abc:defg<hijk>loyz|~\x00'



def init_table():
    table=[]
    for i in range(0,255):
        table.append(255)
    table[82]=0
    v1=ord(key[0])
    v0=1
    while(v1!=0):
        table[v1]=v0
        v1=ord(key[v0])
        v0=v0+1
    table[0xdff-0xdc0]=0x80
    table[0xde4-0xdc0]=0x81
    table[0xe10-0xdc0]=0x82
    table[0xe11-0xdc0]=0x83
    return table


table=init_table()

def sub_1508A(ecx):
    if(ecx>=4):
        return 0
    if(ecx):
        if(ecx!=3):
            return 84
        else:
            return 51
    return 37

def sub_15126(src,len,out,num):
    index_src = 0
    index_edi = 0
    index=0
    arg_0_3=src[3]
    ecx=num
    while(1):
        flag=False
        if(index==0 ):
            flag=True
        elm=table[src[index_src]]
        if(elm<=0xff and elm >=0x80):
            flag=True
        if(flag):
            if(index_edi-1>num):
                break
            if(elm>=0xff or elm <0x80):
                break
            else:
                ecx=(elm+0xFFFFFF80) & 0xffffffff
                arg_0_3=sub_1508A(ecx)
                index_src=index_src+1
                index=index+1

        elm = table[src[index_src]]
        if(elm>=0x80):
            break
        if(elm>=arg_0_3):
            break
        v13=index_edi % arg_0_3
        if(elm<v13):
            data=elm+arg_0_3-v13
        else:
            data=elm-v13
        value=(((((ecx & 0x000000ff )-1) * 0x54)& 0x000000ff)+0x25)& 0x000000ff
        if(ecx==0):
            dl=1
        else:
            dl=0
        dl=(dl-1)& 0x000000ff
        outvalue=(((dl & value ) & 0x000000ff)+(data &0x000000ff))& 0x000000ff
        out.append(chr(outvalue))

        index_edi=index_edi+1
        index_src=index_src+1
        index=index+1
        if(index_src>=len):
            break


def to_list(src):
    sli=[]
    for i in src:
        sli.append(ord(i))
    return sli


def sub_15264(src,out,num):
    if(num):
        num=num-1
    else:
        num=0
    lens=len(src)
    sli = to_list(src)
    sub_15126(sli, lens, out, num)





def sub_152BC(src):
    v2=len(src)
    out = []
    strr = ''
    sub_15264(src,out,v2+63)
    if (len(out) > 0):
        for i in out:
            strr += i
    return strr


def sub_153B6(src):
    out=[]
    v2 = len(src)
    sub_15264(src,out,5*v2+32)
    strr=''
    if(len(out)>0):
        for i in out:
            if(i!=0):
                strr+=i
    return strr

def sub_15436(src):
    out = []
    strr = ''
    v2 = len(src)
    sub_15264(src,out,5*v2+32)
    if (len(out) > 0):
        for i in out:

                strr += i
    return strr



def main():
    src1='$p8jy@dvie<wb[jlovv'
    src2='$GJ[fc%;ob0OiEk'
    src3='$Ka%>il|f%3hDj'
    a=sub_153B6(src1)
    b=sub_15436(src2)
    c=sub_152BC(src3)

    print(a)
    print(b)
    print(c)

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

#main()

def get_xref_list(fn_addr):

    return [addr.frm for addr in idautils.XrefsTo(fn_addr)]


def decode_string_xref(func,decode_func):

    func1= get_xref_list(func)

    for i in func1:
        str_addr=0
        for count in range(0,10):
            head=idc.prev_head(i)
            if(idc.print_insn_mnem(head)=='push'):
                str_addr=idc.get_operand_value(head,0)
                break


        if(str_addr>=0x10000):

            strr=b''
            while(True):
                elm=idc.get_bytes(str_addr, 1)
                str_addr=str_addr+1
                #print(elm)
                if(elm!=b'\x00'):

                    strr+=elm
                else:
                    break
            try:
                src=strr.decode()
            except:
                print(hex(str_addr))
                src=''
            if(src==''):
                continue
            ret=decode_func(src)
            set_comment(i,ret)



decode_string_xref(0x152BC,sub_152BC)
decode_string_xref(0x15436,sub_15436)
decode_string_xref(0x153B6,sub_153B6)