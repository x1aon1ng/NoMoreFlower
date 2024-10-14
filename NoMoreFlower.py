import idautils
import idaapi
import ida_bytes
import idc
import re
from ida_idaapi import plugin_t


def print_title():
    noMoreFlower = """
===========================================================================================================================================================================
,---.   .--.    ,-----.            ,---.    ,---.    ,-----.    .-------.        .-''-.           ________   .---.       ,-----.    .--.      .--.    .-''-.  .-------.     
|    \  |  |  .'  .-,  '.          |    \  /    |  .'  .-,  '.  |  _ _   \     .'_ _   \         |        |  | ,_|     .'  .-,  '.  |  |_     |  |  .'_ _   \ |  _ _   \    
|  ,  \ |  | / ,-.|  \ _ \         |  ,  \/  ,  | / ,-.|  \ _ \ | ( ' )  |    / ( ` )   '        |   .----',-./  )    / ,-.|  \ _ \ | _( )_   |  | / ( ` )   '| ( ' )  |    
|  |\_ \|  |;  \  '_ /  | :        |  |\_   /|  |;  \  '_ /  | :|(_ o _) /   . (_ o _)  |        |  _|____ \  '_ '`) ;  \  '_ /  | :|(_ o _)  |  |. (_ o _)  ||(_ o _) /    
|  _( )_\  ||  _`,/ \ _/  |        |  _( )_/ |  ||  _`,/ \ _/  || (_,_).' __ |  (_,_)___|        |_( )_   | > (_)  ) |  _`,/ \ _/  || (_,_) \ |  ||  (_,_)___|| (_,_).' __  
| (_ o _)  |: (  '\_/ \   ;        | (_ o _) |  |: (  '\_/ \   ;|  |\ \  |  |'  \   .---.        (_ o._)__|(  .  .-' : (  '\_/ \   ;|  |/    \|  |'  \   .---.|  |\ \  |  | 
|  (_,_)\  | \ `"/  \  ) /         |  (_,_)  |  | \ `"/  \  ) / |  | \ `'   / \  `-'    /        |(_,_)     `-'`-'|___\ `"/  \  ) / |  '  /\  `  | \  `-'    /|  | \ `'   / 
|  |    |  |  '. \_/``".'          |  |      |  |  '. \_/``".'  |  |  \    /   \       /         |   |       |        \'. \_/``".'   |    /  \    |  \       / |  |  \    /  
'--'    '--'    '-----'            '--'      '--'    '-----'    ''-'   `'-'     `'-..-'          '---'       `--------`  '-----'    `---'    `---`   `'-..-'  ''-'   `'-'   
===========================================================================================================================================================================                                                                                       
"""
    print(noMoreFlower)


def match_like_jz_jnz():
    # Define patterns for various jump instructions
    patterns = [
        re.compile(rb'(\x70[\x00\x01\x02\x03\x04\x05]\x71[\x00\x01\x02\x03\x04\x05]|\x71[\x00\x01\x02\x03\x04\x05]\x70[\x00\x01\x02\x03\x04\x05])'),  # jo jno
        re.compile(rb'(\x72[\x00\x01\x02\x03\x04\x05]\x73[\x00\x01\x02\x03\x04\x05]|\x73[\x00\x01\x02\x03\x04\x05]\x72[\x00\x01\x02\x03\x04\x05])'),  # jb jnb
        re.compile(rb'(\x74[\x00\x01\x02\x03\x04\x05]\x75[\x00\x01\x02\x03\x04\x05]|\x75[\x00\x01\x02\x03\x04\x05]\x74[\x00\x01\x02\x03\x04\x05])'),  # jz jnz
        re.compile(rb'(\x76[\x00\x01\x02\x03\x04\x05]\x77[\x00\x01\x02\x03\x04\x05]|\x77[\x00\x01\x02\x03\x04\x05]\x76[\x00\x01\x02\x03\x04\x05])'),  # jbe ja
        re.compile(rb'(\x78[\x00\x01\x02\x03\x04\x05]\x79[\x00\x01\x02\x03\x04\x05]|\x79[\x00\x01\x02\x03\x04\x05]\x78[\x00\x01\x02\x03\x04\x05])'),  # js jns
        re.compile(rb'(\x7A[\x00\x01\x02\x03\x04\x05]\x7B[\x00\x01\x02\x03\x04\x05]|\x7B[\x00\x01\x02\x03\x04\x05]\x7A[\x00\x01\x02\x03\x04\x05])'),  # jne jpo
        re.compile(rb'(\x7C[\x00\x01\x02\x03\x04\x05]\x7D[\x00\x01\x02\x03\x04\x05]|\x7D[\x00\x01\x02\x03\x04\x05]\x7C[\x00\x01\x02\x03\x04\x05])'),  # jl jge
        re.compile(rb'(\x7E[\x00\x01\x02\x03\x04\x05]\x7F[\x00\x01\x02\x03\x04\x05]|\x7F[\x00\x01\x02\x03\x04\x05]\x7E[\x00\x01\x02\x03\x04\x05])'),  # jle jg
    ]
    return patterns

def patch_like_jz_jnz():
    print("======Match_like_jz_jnz_pattern Run======")
    
    # Get all patterns from match_like_jz_jnz function
    patterns = match_like_jz_jnz()
    
    for seg_start in idautils.Segments():
        seg_end = idc.get_segm_end(seg_start)
        
        # Get the entire segment's binary data
        segment_data = idc.get_bytes(seg_start, seg_end - seg_start)
        seg_name = idc.get_segm_name(seg_start)
        
        # Check if the segment is a text segment
        if seg_name.lower() != ".text":
            continue
        
        for pattern in patterns:
            #print(f"[*] pattern: {pattern} is matching")
            # Use regex to find all matches for the current pattern
            for match in re.finditer(pattern, segment_data):
                match_start = match.start() + seg_start
                match_end = match.end() + seg_start
                #print(f"[*] pattern: {pattern} matched")
                
                #if idc.is_code(idc.get_full_flags(match_start)):
                first_instruction = idc.GetDisasm(match_start)
                second_instruction = idc.GetDisasm(match_start + 2)
                    
                print(f"[*] Address: {hex(match_start)}, Instruction: {first_instruction}")
                print(f"[*] Address: {hex(match_start + 2)}, Instruction: {second_instruction}")
                
                # Determine if it's a jump instruction and get the target address
                if segment_data[match.start()] == 0x74 or segment_data[match.start()] == 0x76 or segment_data[match.start()] == 0x78 or segment_data[match.start()] == 0x7A or segment_data[match.start()] == 0x7C or segment_data[match.start()] == 0x7E:  # jz
                    invalid_code_end_addr = idc.get_operand_value(match_start, 0)
                elif segment_data[match.start()] == 0x75 or segment_data[match.start()] == 0x77 or segment_data[match.start()] == 0x79 or segment_data[match.start()] == 0x7B or segment_data[match.start()] == 0x7D or segment_data[match.start()] == 0x7F:  # jnz
                    invalid_code_end_addr = idc.get_operand_value(match_start + 2, 0)
                else:
                    continue  # Skip other jump instructions
                                
                # Replace the matched machine code with NOP (0x90)
                ida_bytes.patch_bytes(match_start, b'\x90\x90\x90\x90')
                
                # Fill the invalid code after the jump instruction with NOPs
                invalid_code_num = 0
                for invalid_code_addr in range(match_start + 4, invalid_code_end_addr):
                    ida_bytes.patch_byte(invalid_code_addr, 0x90)
                    print("found invalid code at {:#x} ".format(invalid_code_addr))
                    invalid_code_num += 1
                print("Patched {:d} bytes invalid codes with Nops".format(invalid_code_num))
    
    print("======Match_like_jz_jnz_pattern End======\n")



def match_like_xor_jz():
    patterns = [
        re.compile(rb'\x33[\xC0\xD8]\x74[\x01\x02\x03]'),#xor jz 
        re.compile(rb'\xF8\x73.'),#clc jnb
    ]
    return patterns

def patch_like_xor_jz():
    print("======Match_like_xor_jz_pattern Run======")
    patterns = match_like_xor_jz()
    # 遍历所有段
    for seg_start in idautils.Segments():
        seg_end = idc.get_segm_end(seg_start)
        
        # 获取整个段的二进制数据
        segment_data = idc.get_bytes(seg_start, seg_end - seg_start)
        seg_name = idc.get_segm_name(seg_start)
        #判断是否为text段
        if seg_name.lower() != ".text":
            continue
        
        for pattern in patterns:
        # 使用正则表达式在段数据中查找所有匹配
            for match in re.finditer(pattern, segment_data):
                match_start = match.start() + seg_start
                match_end = match.end() + seg_start
                
                #if idc.is_code(idc.get_full_flags(match_start)):
                    # 获取指令的汇编代码
                if pattern == patterns[0]:
                    second_code_position = match_start + 2
                    patch_code = b'\x90\x90\x90\x90'
                    if idc.is_code(match_start + 4):
                        print(f"is code at {match_start + 4}")
                        continue
                elif pattern == patterns[1]:
                    second_code_position = match_start + 1
                    patch_code = b'\x90\x90\x90'

                first_instruction = idc.GetDisasm(match_start)
                second_instruction = idc.GetDisasm(second_code_position)
                    
                print(f"[*] Address: {hex(match_start)}, Instruction: {first_instruction}")
                print(f"[*] Address: {hex(second_code_position)}, Instruction: {second_instruction}")
                    
                    # 获取 jz 跳转的目标地址
                invalid_code_end_addr = idc.get_operand_value(second_code_position, 0)
                    
                    # 将匹配到的机器码替换为 NOP（0x90）
                ida_bytes.patch_bytes(match_start, patch_code)

                    # 填充跳转指令之后的无效代码
                invalid_code_num = 0
                #junk code的位置应当时第二条指令之后
                for invalid_code_addr in range(second_code_position + 2, invalid_code_end_addr):
                    ida_bytes.patch_byte(invalid_code_addr, 0x90)
                    print("found invalid code at {:#x} ".format(invalid_code_addr))
                    invalid_code_num += 1
                print("Patched {:d} bytes invalid codes with Nops".format(invalid_code_num))
    
    print("======Match_like_xor_jz_pattern End======\n")


def match_like_call():
    patterns = [
        re.compile(rb'\x50\xE8.\x00\x00\x00.+\x58\x58'),#call pop eax
        re.compile(rb'\xE8[\x01\x02\x03]\x00\x00\x00.{0,3}\x83\xC4\x04'),#call add esp 4
        re.compile(rb'\xE8[\x01\x02\x03]\x00\x00\x00.{0,3}\x36\x83\x04\x24\x08\xC3'),#call add esp  ret
        re.compile(rb'\xE8\x00\x00\x00\x00\x58\x83\xC0\x0C\x50\xC3....\xC3'),
    ]
    return patterns

def patch_like_call():
    print("======Match_like_call_pattern Run======")
    for seg_start in idautils.Segments():
            seg_end = idc.get_segm_end(seg_start)
            patterns = match_like_call()
            
            # 获取整个段的二进制数据
            segment_data = idc.get_bytes(seg_start, seg_end - seg_start)
            seg_name = idc.get_segm_name(seg_start)
            #判断是否为text段
            if seg_name.lower() != ".text":
                continue
            
            for pattern in patterns:
                segment_data = idc.get_bytes(seg_start, seg_end - seg_start)
            # 使用正则表达式在段数据中查找所有匹配
                for match in re.finditer(pattern, segment_data):
                    match_start = match.start() + seg_start
                    match_end = match.end() + seg_start
                    
                    #if idc.is_code(idc.get_full_flags(match_start)):
                        # 获取指令的汇编代码
                    second_code_position = match_start + 2
                    if pattern == patterns[0]:#call pop eax
                        #如果是call pop eax类型的
                        second_code_position = idc.get_operand_value(match_start + 1,0)
                        invalid_code_start_addr = match_start + 6#junk code开始的位置
                        nop_code_after_junk = 2
                        patch_code = b'\x90\x90\x90\x90\x90\x90'
                    elif pattern == patterns[1]:#call add esp 4
                        second_code_position = idc.get_operand_value(match_start,0)
                        invalid_code_start_addr = match_start + 5
                        nop_code_after_junk = 3
                        patch_code = b'\x90\x90\x90\x90\x90'
                    elif pattern == patterns[2]:
                        second_code_position = idc.get_operand_value(match_start,0)
                        invalid_code_start_addr = match_start + 5
                        nop_code_after_junk = 6
                        patch_code = b'\x90\x90\x90\x90\x90'
                        if not idc.is_code(second_code_position + 6):
                            nop_code_after_junk += 1
                    elif pattern == patterns[3]:
                        print(f"[*] Address: {hex(match_start)}, Instruction: {idc.GetDisasm(match_start)}")
                        ida_bytes.patch_bytes(match_start,b'\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90')
                        print(f"Patched 16 bytes codes at {hex(match_start)}")
                        continue

                    first_instruction = idc.GetDisasm(match_start)
                    second_instruction = idc.GetDisasm(second_code_position)
                        
                    print(f"[*] Address: {hex(match_start)}, Instruction: {first_instruction}")
                    print(f"[*] Address: {hex(second_code_position)}, Instruction: {second_instruction}")
                        
                    invalid_code_end_addr = second_code_position
                        
                        # nop junk code之前的部分
                    ida_bytes.patch_bytes(match_start, patch_code)
                    invalid_code_num = 0
                    #junk code的位置应当时第二条指令之后
                    for invalid_code_addr in range(invalid_code_start_addr, invalid_code_end_addr):
                        ida_bytes.patch_byte(invalid_code_addr, 0x90)
                        print("found invalid code at {:#x} ".format(invalid_code_addr))
                        invalid_code_num += 1
                    print("Patched {:d} bytes invalid codes with Nops".format(invalid_code_num))

                        #nop junk code 之后的部分
                    need_nop_num_after = 0
                    for need_nop in range(second_code_position,second_code_position + nop_code_after_junk):
                        ida_bytes.patch_byte(need_nop,0x90)
                        need_nop_num_after += 1
                    print(f"Patched {need_nop_num_after} bytes at {second_instruction}")
    
    print("======Match_like_call_pattern End======\n")





class NoMoreFlower_Plugin_t(plugin_t):
    comment = "a simple tool for junk code"
    help = "unknown"

    flags = idaapi.PLUGIN_KEEP

    wanted_name = "NoMoreFlower"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self,arg):
        # 调用函数
        print_title()
        patch_like_jz_jnz()
        patch_like_xor_jz()
        patch_like_call()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return NoMoreFlower_Plugin_t()

