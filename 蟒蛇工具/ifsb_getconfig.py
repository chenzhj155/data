import pefile
import struct

from malduck import aplib
# 样本 时间为2020 Jul 7




FILE_PATH = 'c9bd16862ae56ec22ca70e30af4a4c8d_mainwork'
file_data = open(FILE_PATH, 'rb').read()
pe = pefile.PE(data=file_data)


end_of_last_section = pe.NT_HEADERS.FILE_HEADER.SizeOfOptionalHeader + pe.DOS_HEADER.e_lfanew + 0x18 + 0x28 * pe.FILE_HEADER.NumberOfSections

def get_configdata(jj_elm,file_data):
    foa = pe.get_offset_from_rva(jj_elm['rva'])
    size = jj_elm['size']
    encrypt_key = jj_elm['encrypt_key']
    if(jj_elm['decode']==0):
        count=int(size/4)
        out=bytes()
        for i in range(count):
            int1 = struct.unpack("<i", file_data[foa+i*4:foa+i*4+4])[0]
            int2=int1-encrypt_key
            encrypt_key =int1

            out=out+struct.pack("<q",int2)[0:4]

        if(size-count*4>0):
            a=size-count*4
            for i in range(a):
                out=out+struct.pack("<c",file_data[size-4+i:size-4+i+1])
        return out
    else:
        #aplib
        out = bytes()
        aplibdata=aplib.decompress(file_data[foa:foa+size])
        if(size>=4):
            int1=struct.unpack("<I", aplibdata[0:4])[0]
            int1=int1^encrypt_key
            out=struct.pack("<q",int1)[0:4]+aplibdata[4:-1]
        else:
            return aplibdata

        return out
def get_JJBlock(file_data,off):

    jjblock=[]
    jj_elm={}
    i=0
    flag=False
    while 1:
        jj_elm={}
        sign=file_data[off:off+2]
        off=off+2
        if(sign==b'JJ'):
            flag=True
            jj_elm['sign']='JJ'

            #jj_elm['fill_count']=struct.unpack("<B", file_data[off+i:off+i+1])[0]
            off=off+1

            c = struct.unpack("<B", file_data[off:off+1])[0]
            jj_elm['decode']=c&1
            #jj_elm['invalid']=c&2
            off=off+1

            jj_elm['encrypt_key']=struct.unpack("<i", file_data[off:off+4])[0]
            off=off+4
            jj_elm['crc_id']=struct.unpack("<I", file_data[off:off+4])[0]
            off=off+4
            jj_elm['rva']=struct.unpack("<I", file_data[off:off+4])[0]
            off=off+4
            jj_elm['size'] = struct.unpack("<I", file_data[off :off  + 4])[0]
            off=off+4
            jjblock.append(jj_elm)
        else:
            if(flag):
                break
            else:
                continue

    return jjblock

jjblock=get_JJBlock(file_data,end_of_last_section)

# 解析第一层配置，下一层是否存在配置需根据CRCid 判断




def parse_subconfig(data):
    count=struct.unpack("<I", data[0:4])[0]
    subconfig={}
    if(count==0):
        pass
    else:
        start=8

        for i in range(count):
            crc_id = struct.unpack("<I", data[start:start + 4])[0]
            flag=struct.unpack("<B", data[start+4:start + 5])[0]&1
            if(flag!=0):
                off=struct.unpack("<I", data[start+8:start +8+ 4])[0]+start
            else:
                off=struct.unpack("<I", data[start+8:start +8+ 4])[0]
            index=0
            for elm in data[off:-1]:
                if(elm==0):
                    break
                else:
                    index=index+1
            subconfig[crc_id]=data[off:off+index]



            start=start+24

    return  subconfig

for i in jjblock:
    if(i['crc_id']==0xE1285E64):
        # 加密url时的加密密钥
        data=get_configdata(i,file_data)
        print('serpent_key:\n')
        a=data.hex(' ', -4)
        ccount=0
        for value  in a.split(' '):
            ccount=ccount+1
            if(ccount==4):
                ccount=0
                print('0x'+value,end=' ')
                print('\n')
            else:
                print('0x' + value, end=' ')
    if (i['crc_id'] == 0xD722AFCB):
        # client ini
        client_ini=get_configdata(i, file_data)
        subconfig=parse_subconfig(client_ini)
        if(subconfig is not  None):

            for  dickey in subconfig.keys():
                #print(subconfig[dickey].decode('utf-8'))
                if(dickey==0x4FA8693E):
                    print('downloader_MainWorker CC'+subconfig[dickey].decode('utf-8'))
                if (dickey == 0xdf351e24):
                    print('downloader torClinet CC' + subconfig[dickey].decode('utf-8'))
                if (dickey == 0xd0665bf6):
                    print('Upload CC' + subconfig[dickey].decode('utf-8'))
