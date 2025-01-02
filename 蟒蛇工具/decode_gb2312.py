# -*- coding: utf-8 -*-
import idaapi
import idautils
import idc
import codecs

class GB2312StringDecoder:
    def __init__(self):
        self.encoding = 'gb2312'  # 指定编码类型

    def is_printable(self, data):
        """
        判断数据是否可能是 GB2312 编码的字符串
        """
        try:
            data.decode(self.encoding)
            return True
        except (UnicodeDecodeError, AttributeError):
            return False

    def scan_strings(self, start, end):
        """
        扫描指定内存区域，查找 GB2312 编码的字符串
        """
        current_addr = start
        results = []

        while current_addr < end:
            byte_seq = b''
            while current_addr < end:
                byte = idc.get_wide_byte(current_addr)
                if byte == 0:  # 字符串结束符
                    break
                byte_seq += bytes([byte])
                current_addr += 1

            if len(byte_seq) > 1 and self.is_printable(byte_seq):
                try:
                    decoded_str = byte_seq.decode(self.encoding)
                    results.append((current_addr - len(byte_seq), decoded_str))
                except UnicodeDecodeError:
                    pass

            current_addr += 1  # 跳过空字节

        return results

    def annotate_strings(self, results):
        """
        在 IDA 的反汇编视图中添加注释
        """
        for addr, string in results:
            idc.set_cmt(addr, f"GB2312: {string}", 0)

    def run(self):
        """
        主函数：扫描数据段并注释字符串
        """
        print("开始扫描 GB2312 字符串...")

        for seg in idautils.Segments():
            seg_name = idc.get_segm_name(seg)
            if seg_name in ['.data', '.rdata']:  # 只扫描数据段
                start = idc.get_segm_start(seg)
                end = idc.get_segm_end(seg)
                print(f"扫描段: {seg_name} ({hex(start)} - {hex(end)})")

                results = self.scan_strings(start, end)
                self.annotate_strings(results)

        print("GB2312 字符串扫描完成！")

# 创建并运行插件
decoder = GB2312StringDecoder()
decoder.run()
