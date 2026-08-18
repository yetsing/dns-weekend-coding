import dataclasses
import random
import socket
import struct
import time
from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
from typing import List, Literal, TypeAlias

random.seed(1)


@dataclass
class DNSHeader:
    id: int
    flags: int
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0


@dataclass
class DNSQuestion:
    name: bytes
    type_: int
    class_: int


def header_to_bytes(header):
    fields = dataclasses.astuple(header)
    return struct.pack("!HHHHHH", *fields)


def parse_header(reader):
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)


def question_to_bytes(question):
    return question.name + struct.pack("!HH", question.type_, question.class_)


def parse_question(reader):
    name = decode_name_simple(reader)
    type_, class_ = struct.unpack("!HH", reader.read(4))
    return DNSQuestion(name, type_, class_)


def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def decode_name_simple(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b".".join(parts)


def decode_name(reader):
    return decode_name_wrapper(reader, 10)


def decode_name_wrapper(reader, count):
    if count <= 0:
        raise ValueError("Too many indirections in DNS name decoding")
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader, count))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def decode_compressed_name(length, reader, count):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name_wrapper(reader, count - 1)
    reader.seek(current_pos)
    return result


TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
CLASS_IN = 1

DNSRecordType: TypeAlias = Literal["A", "NS", "CNAME", 1, 2, 5]
TYPE_MAP = {
    "A": TYPE_A,
    "NS": TYPE_NS,
    "CNAME": TYPE_CNAME,
}


def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    header = DNSHeader(id=id, flags=0, num_questions=1)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)


@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes


def parse_record(reader):
    name = decode_name(reader)
    data = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    # It would be more hygenic here to store the raw data and the
    # parsed result in separate fields in DNSRecord, but we're lazy.
    if type_ == TYPE_NS:  # here's the code we're adding
        data = decode_name(reader)
    elif type_ == TYPE_A:
        data = ip_to_string(reader.read(data_len))
    elif type_ == TYPE_CNAME:
        data = decode_name(reader)
    else:
        data = reader.read(data_len)
    return DNSRecord(name, type_, class_, ttl, data)


@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]


def parse_dns_packet(data):
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)


def send_query(ip_address, domain_name, record_type, retries=3, timeout=5):
    for attempt in range(retries):
        query = build_query(domain_name, record_type)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (ip_address, 53))
            data, _ = sock.recvfrom(1024)
            return parse_dns_packet(data)
        except socket.timeout:
            print(
                f"    Timeout querying {ip_address} (attempt {attempt + 1}/{retries})"
            )
        finally:
            sock.close()
    raise socket.timeout(f"No response from {ip_address} after {retries} attempts")


def ip_to_string(ip):
    return ".".join(str(b) for b in ip)


def lookup_domain(domain_name):
    response = send_query("8.8.8.8", domain_name, TYPE_A)
    return ip_to_string(response.answers[0].data)


def get_answer(packet):
    # return the first A record in the Answer section
    for x in packet.answers:
        if x.type_ == TYPE_A:
            return x.data


def get_cname(packet):
    # return the first CNAME record in the Answer section
    for x in packet.answers:
        if x.type_ == TYPE_CNAME:  # CNAME type
            return x.data.decode("utf-8")


def get_nameserver_ip(packet):
    # return the first A record in the Additional section
    for x in packet.additionals:
        if x.type_ == TYPE_A:
            return x.data


def get_nameserver(packet):
    # return the first NS record in the Authority section
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode("utf-8")


@lru_cache(maxsize=10)
def resolve(domain_name: str, record_type: DNSRecordType) -> str:
    nameserver = "198.41.0.4"
    if isinstance(record_type, str):
        record_type = TYPE_MAP.get(record_type.upper())
        if record_type is None:
            raise ValueError(f"Invalid record type: {record_type}")
    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver, domain_name, record_type)
        if ip := get_answer(response):
            return ip
        elif cname := get_cname(response):
            return resolve(cname, record_type)
        elif nsIP := get_nameserver_ip(response):
            nameserver = nsIP
        # New case: look up the nameserver's IP address if there is one
        elif ns_domain := get_nameserver(response):
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            # print(response)
            raise Exception("something went wrong")


if __name__ == "__main__":
    print("Resolving domain names...")
    res = resolve("twitter.com", "A")
    print("Got IP:", res)
    print()

    # CNAME example
    print("Resolving domain names...")
    res = resolve("docs.helpscout.com", TYPE_A)
    print("Got IP:", res)
    print()

    data1 = "129581800001000100000000076578616d706c6503636f6d0000010001c01d000100010000012c000408080808"
    try:
        parse_dns_packet(bytes.fromhex(data1))
    except ValueError as e:
        print("Correctly caught error for self-referencing pointer:", e)
    data2 = "123481800001000100000000076578616d706c6503636f6d0000010001c01d000100010000012c000408080808"
    try:
        parse_dns_packet(bytes.fromhex(data2))
    except ValueError as e:
        print("Correctly caught error for loop pointer:", e)

    # Test cache
    s = time.monotonic()
    resolve("twitter.com", "A")
    e = time.monotonic()
    assert e - s < 0.1, "Cached lookup took too long"
