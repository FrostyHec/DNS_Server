import socketserver
import socket
from typing import Tuple, List, Dict

TYPE_NS = 2
TYPE_A = 1
TYPE_AAAA = 28
TYPE_CNAME = 5


def parse_ipv6(data: bytes, idx: int) -> Tuple[str, int]:
    ip = ""
    for i in range(8):
        val = int.from_bytes(data[idx + i * 2:idx + i * 2 + 2], byteorder='big')
        ip += str(hex(val))[2:]
        ip += ":"
    return shorten_ipv6(ip[:-1]), idx + 16


def encode_ipv6(ipv6: str) -> Tuple[bytes, int]:
    res = b''
    ipv6s = extend_ipv6(ipv6).split(':')
    for seg in ipv6s:
        res += int(seg, 16).to_bytes(2, byteorder='big')
    return res, 16


def shorten_ipv6(ipv6: str) -> str:  # 真难写, UGLY Code
    arr = ipv6.split(':')
    zero_len, seg_idx, max_zero_len, max_zero_seg_idx = 0, -1, 0, -1
    for i in range(len(arr)):
        if arr[i] == '0':
            if seg_idx == -1:
                seg_idx = i
            zero_len += 1
            if zero_len > max_zero_len:
                max_zero_len = zero_len
                max_zero_seg_idx = seg_idx
        else:
            zero_len = 0
            seg_idx = -1
    if max_zero_len == 0:
        return ipv6
    res = ""
    seg_used = False
    for i in range(len(arr)):
        if i < max_zero_seg_idx or i >= max_zero_seg_idx + max_zero_len:  # 不需要过滤
            res += arr[i]
            res += ":"
        else:
            if not seg_used:
                if max_zero_seg_idx == 0 or max_zero_seg_idx + max_zero_len == len(arr):
                    res += "::"
                else:
                    res += ":"
                seg_used = True
    if max_zero_len == 8:
        return '::'
    return res[:-1]


def extend_ipv6(ipv6: str) -> str:
    if ipv6 == '::':
        return '0:0:0:0:0:0:0:0'
    parts = ipv6.split('::')
    if len(parts) == 1:  # 不是缩写版本的
        return ipv6
    left, right = parts[0], parts[1]
    full_length = 0
    if left != '':
        full_length += len(left.split(':'))
    if right != '':
        full_length += len(right.split(':'))
    res = left + ':' + '0:' * (8 - full_length) + right
    if left == '':
        res = res[1:]
    elif right == '':
        res = res[:-1]
    return res


def parse_ipv4(data: bytes, idx: int) -> Tuple[str, int]:
    ip = ""
    for i in range(4):
        ip += str(data[idx + i]) + "."
    return ip[:-1], idx + 4


def encode_ipv4(ip: str) -> Tuple[bytes, int]:
    ips = ip.split('.')
    res = b''
    for seg in ips:
        res += int(seg).to_bytes(1, byteorder='big')
    return res, 4


def parse_dns_name(whole_data: bytes, idx: int) -> Tuple[
    str, int]:  # str,idx , will use offset to get things from previous data
    name = ""
    pointer_idx = idx
    point_back = False
    while whole_data[pointer_idx] != 0:
        # parsing number
        len = int.from_bytes(whole_data[pointer_idx:pointer_idx + 1], byteorder='big')
        pointer_idx += 1
        if len >= 192:  # pointer
            pointer_idx = ((len - 192) << 8) + int.from_bytes(whole_data[pointer_idx:pointer_idx + 1], byteorder='big')
            if not point_back:  # 第一个指针
                idx += 1
            point_back = True
            continue
        # parsing name

        name += whole_data[pointer_idx:pointer_idx + len].decode('utf-8') + "."
        pointer_idx += len
        if not point_back:
            idx = pointer_idx
    # 处理跟服务器的情况
    name = name[:-1]
    if name == '':
        name = 'root'
    return name, idx + 1


def encode_dns_name(name: str, prev_len: int, prev_dict: Dict[str, int]) -> Tuple[bytes, int, Dict[str, int]]:
    '''
    1. 如果name为空，返回b'\x00',1
    2. 一段一段地取出域名节，然后判断后面部分是否在prev_dict中，如果是就构造指针，否则就构造长度+字符串
    :param name:
    :return: 返回编码后的bytes和长度
    '''
    if name == 'root':
        return b'\x00', 1, prev_dict
    name = '.' + name
    res = b''
    i = 0
    while i < len(name):
        if name[i] != '.':
            i += 1
            continue
        key = name[i + 1:]
        if key in prev_dict:  # 指针模式
            val = prev_dict[key] + (192 << 8)
            res += val.to_bytes(2, byteorder='big')
            return res, len(res), prev_dict  # 不用在指针后加全0chunk
        # 普通模式
        i += 1
        begin = i
        while i < len(name) and name[i] != '.':  # 找到chunck的len,注意这个chunck找到i停留在.上，不用++
            i += 1
        seg = name[begin:i]
        a = len(res)
        res += len(seg).to_bytes(1, byteorder='big')
        res += seg.encode('utf-8')
        # assert a + len(seg) + 1 == len(res)
        # 添加name[begin:]到prev_dict中,其位置为begin-1+prev_len
        prev_dict[name[begin:]] = begin - 1 + prev_len
    return res + b'\x00', len(res) + 1, prev_dict
    # # no compress version
    # name = name.split('.')
    # res = b''
    # for seg in name:
    #     res += len(seg).to_bytes(1, byteorder='big')
    #     res += seg.encode('utf-8')
    # return res + b'\x00', len(res) + 1


class DNSHeader:

    def __init__(self, *args, **kwargs):  # You can modify the input of __init__ function as you like
        self.id: int = kwargs['id']
        self.flag: bytes = kwargs['flag']
        self.qdcount: int = kwargs['qdcount']
        self.ancount: int = kwargs['ancount']
        self.nscount: int = kwargs['nscount']
        self.arcount: int = kwargs['arcount']

    @classmethod
    def from_wire(cls, data: bytes):
        id = int.from_bytes(data[0:2], byteorder="big")
        flag = data[2:4]
        qdcount = int.from_bytes(data[4:6], byteorder="big")
        ancount = int.from_bytes(data[6:8], byteorder="big")
        nscount = int.from_bytes(data[8:10], byteorder="big")
        arcount = int.from_bytes(data[10:12], byteorder="big")
        return cls(id=id, flag=flag, qdcount=qdcount, ancount=ancount, nscount=nscount, arcount=arcount)

    def __str__(self):
        # Don't change this function
        return f'ID: {self.id} Flag: {self.flag} QDCOUNT: {self.qdcount} ANCOUNT: {self.ancount} NSCOUNT: {self.nscount} ARCOUNT: {self.arcount}'

    def encoder_bytes(self) -> bytes:
        id_bytes = self.id.to_bytes(2, byteorder='big')
        qdcount_bytes = self.qdcount.to_bytes(2, byteorder='big')
        ancount_bytes = self.ancount.to_bytes(2, byteorder='big')
        nscount_bytes = self.nscount.to_bytes(2, byteorder='big')
        arcount_bytes = self.arcount.to_bytes(2, byteorder='big')
        return (id_bytes + self.flag + qdcount_bytes +
                ancount_bytes + nscount_bytes + arcount_bytes)

    def __eq__(self, other):
        if not isinstance(other, DNSHeader):
            return False
        return (self.id == other.id
                and self.flag == other.flag
                and self.qdcount == other.qdcount
                and self.ancount == other.ancount
                and self.nscount == other.nscount
                and self.arcount == other.arcount)


class DNSQuestion:

    def __init__(self, *args, **kwargs):  # You can modify the input of __init__ function as you like
        self.qname: str = kwargs['qname']
        self.qtype: int = kwargs['qtype']
        self.qclass: int = kwargs['qclass']
        self.next_idx: int = kwargs['next_idx']

    @classmethod
    def from_wire(cls, data: bytes, idx: int = 0):  # Don't change the input of this function
        # parsing qname field
        qname, idx = parse_dns_name(data, idx)
        qtype = int.from_bytes(data[idx:idx + 2], byteorder='big')
        qclass = int.from_bytes(data[idx + 2:idx + 4], byteorder='big')
        return cls(qname=qname, qtype=qtype, qclass=qclass, next_idx=idx + 4)

    def __str__(self):
        # Don't change this function
        return f'QNAME: {self.qname} QTYPE: {self.qtype} QCLASS: {self.qclass}'

    def encode_bytes(self, previous_len: int, previous_dict: Dict[str, int]) -> Tuple[bytes, Dict[str, int]]:
        '''
        传入上一段的len和字符串->chunck的字典，返回当前段编码，加上先前段后当前段的长度与添加了的chunck字典
        :param previous_len:
        :param previous_dict:
        :return:
        '''
        qname_bytes, _, previous_dict = encode_dns_name(self.qname, previous_len, previous_dict)
        qtype_bytes = self.qtype.to_bytes(2, byteorder='big')
        qclass_bytes = self.qclass.to_bytes(2, byteorder='big')
        return qname_bytes + qtype_bytes + qclass_bytes, previous_dict

    def __eq__(self, other):
        if not isinstance(other, DNSQuestion):
            return False
        return (self.qname == other.qname
                and self.qtype == other.qtype
                and self.qclass == other.qclass)


class DNSRR:

    def __init__(self, *args, **kwargs):  # You can modify the input of __init__ function as you like
        self.name: str = kwargs['name']
        self.type: int = kwargs['type']
        self.class_: int = kwargs['class_']
        self.ttl: int = kwargs['ttl']
        self.rdlength: int = kwargs['rdlength']
        self.rdata = kwargs['rdata']
        self.next_idx: int = kwargs['next_idx']

    @classmethod
    def from_wire(cls, data: bytes, idx: int):
        name, idx = parse_dns_name(data, idx)
        type = int.from_bytes(data[idx:idx + 2], byteorder='big')
        idx += 2
        class_ = int.from_bytes(data[idx:idx + 2], byteorder='big')
        idx += 2
        ttl = int.from_bytes(data[idx:idx + 4], byteorder='big')
        idx += 4
        rdlength = int.from_bytes(data[idx:idx + 2], byteorder='big')
        idx += 2
        prev = idx
        if type == TYPE_NS:  # NS
            rdata, idx = parse_dns_name(data, idx)
        elif type == TYPE_A:  # A
            rdata, idx = parse_ipv4(data, idx)
        elif type == TYPE_AAAA:  # AAAA
            rdata, idx = parse_ipv6(data, idx)
        elif type == TYPE_CNAME:  # CNAME
            rdata, idx = parse_dns_name(data, idx)
        else:
            # other types, store as bytes
            rdata, idx = data[idx:idx + rdlength], idx + rdlength
        # assert prev + rdlength == idx
        return cls(name=name, type=type, class_=class_, ttl=ttl, rdlength=rdlength, rdata=rdata,
                   next_idx=idx)

    def __str__(self):
        # Don't change this function
        return f'NAME: {self.name} TYPE: {self.type} CLASS: {self.class_} TTL: {self.ttl} RDLENGTH: {self.rdlength} RDATA: {self.rdata}'

    def encode_bytes(self, previous_len: int, previous_dict: Dict[str, int]) -> Tuple[bytes, Dict[str, int]]:
        name_bytes, length, previous_dict = encode_dns_name(self.name, previous_len, previous_dict)
        previous_dict[self.name] = previous_len
        type_bytes = self.type.to_bytes(2, byteorder='big')
        class_bytes = self.class_.to_bytes(2, byteorder='big')
        ttl_bytes = self.ttl.to_bytes(4, byteorder='big')
        previous_len += length + 10
        if self.type == TYPE_NS or self.type == TYPE_CNAME:
            rdata_bytes, part_len, previous_dict = encode_dns_name(self.rdata, previous_len, previous_dict)
        elif self.type == TYPE_A:
            rdata_bytes, part_len = encode_ipv4(self.rdata)
        elif self.type == TYPE_AAAA:
            rdata_bytes, part_len = encode_ipv6(self.rdata)
        else:
            rdata_bytes, part_len = self.rdata, len(self.rdata)
        rdlength_bytes = len(rdata_bytes).to_bytes(2, byteorder='big')
        return (name_bytes + type_bytes + class_bytes
                + ttl_bytes + rdlength_bytes + rdata_bytes,
                previous_dict
                )

    def __eq__(self, other):
        if not isinstance(other, DNSRR):
            return False
        return (self.name == other.name
                and self.type == other.type
                and self.class_ == other.class_
                and self.ttl == other.ttl
                and self.rdlength == other.rdlength
                and self.rdata == other.rdata)


class DNSMessage:

    def __init__(self, *args, **kwargs):  # You can modify the input of __init__ function as you like
        self.header: DNSHeader = kwargs['header']
        self.question: DNSQuestion = kwargs['question']  # We make sure there is only one question during the test
        self.answer: list[DNSRR] = kwargs['answer']  # a list of DNSRR
        self.authority: list[DNSRR] = kwargs['authority']  # a list of DNSRR
        self.additional: list[DNSRR] = kwargs['additional']  # a list of DNSRR

    @classmethod
    def from_wire(cls, data: bytes):  # Don't change the input of this function
        header = DNSHeader.from_wire(data)
        idx = 12
        question = DNSQuestion.from_wire(data, idx)
        idx = question.next_idx
        answer = []
        for i in range(header.ancount):
            rr = DNSRR.from_wire(data, idx)
            idx = rr.next_idx
            answer.append(rr)
        authority = []
        for i in range(header.nscount):
            rr = DNSRR.from_wire(data, idx)
            idx = rr.next_idx
            authority.append(rr)
        additional = []
        for i in range(header.arcount):
            rr = DNSRR.from_wire(data, idx)
            idx = rr.next_idx
            additional.append(rr)
        return cls(header=header, question=question, answer=answer, authority=authority, additional=additional)

    def encode_bytes(self) -> bytes:
        res = self.header.encoder_bytes()
        domain_dict = {}
        seg, domain_dict = self.question.encode_bytes(len(res), domain_dict)
        res += seg
        for rr in self.answer + self.authority + self.additional:
            seg, domain_dict = rr.encode_bytes(len(res), domain_dict)
            res += seg
        return res

    def __eq__(self, other):
        if not isinstance(other, DNSMessage):
            return False
        return (self.header == other.header
                and self.question == other.question
                and self.answer == other.answer
                and self.authority == other.authority
                and self.additional == other.additional)


class MyLocalDNSServerHandler(socketserver.BaseRequestHandler):

    def __init__(self, request, client_address, server):
        """
        We list the root DNS server (a-g) here.
        You can use this list to query the root server.
        """
        self.root_dns_address = ['198.41.0.4', '199.9.14.201', '192.33.4.12',
                                 '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4']

        super().__init__(request, client_address, server)

    def change_rd_bit(self, data):
        """
        :param data: Input message from client dig
        Change the rd bit into 0, since the default query of dig is recursive
        """
        flag = bytes.fromhex('0000')
        return data[0:2] + flag + data[4:]

    def recover_rd_bit(self, data) -> bytes:
        '''
        返回的时候把rd设回1
        :param data:
        :return:
        '''
        # 修改recrusive字段
        flag_1 = data[2] + 1
        flag_2 = data[3]
        if flag_2 < 128:  # set recrusive available
            flag_2 += 128
        return (data[0:2] + flag_1.to_bytes(1, byteorder='big') +
                flag_2.to_bytes(1, byteorder='big') + data[4:])

    def query_server(self, data, server_ip_list, server_port=53):
        """
        You may need this function to query the DNS server
        :data: the message to send to the server
        :server_ip_list: a list of ip addresses of the server
        :server_port: the port of the server default to 53
        """

        if len(server_ip_list) == 0:
            raise ValueError('There is no server ip address to query.')
        timeout_limit = 3
        while True:
            try:
                server_ip = server_ip_list[0]
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server_socket.sendto(data, (server_ip, server_port))
                server_socket.settimeout(timeout_limit)  # time out after 3 seconds
                response, _ = server_socket.recvfrom(10240)
                server_socket.settimeout(None)
                server_socket.close()
                return response
            except:
                print(f'Failed to connect to {server_ip_list[0]} with time out {timeout_limit}s. Try another server.')
                server_ip_list.pop(0)
                if len(server_ip_list) == 0:
                    raise ValueError('There is no avaliable server.')

    def handle(self):
        data = self.request[0].strip()  # data from the client (dig in this case)
        socket = self.request[1]  # connection with the client
        data = self.change_rd_bit(data)  # change recursive query to iterative query

        response = self.iterative_query(data, self.root_dns_address)
        response = self.recover_rd_bit(response)  # 恢复rr和rd

        socket.sendto(response, self.client_address)

    def iterative_query(self, data: bytes, server_ip_list: List[str]) -> bytes:
        response_data = self.query_server(data, server_ip_list)
        resp_message = DNSMessage.from_wire(response_data)
        if len(resp_message.answer) > 0:  # got answer
            cname = None
            for rr in resp_message.answer:
                if rr.type == TYPE_A:
                    return response_data
                elif rr.type == TYPE_CNAME:
                    cname = rr.rdata
            # only cname
            if cname:  # send another request to cname field and get question
                cname_data = self.iterative_query(self.construct_query(cname).encode_bytes(), self.root_dns_address)
                cname_msg = DNSMessage.from_wire(cname_data)
                add_an_len = len(cname_msg.answer)
                resp_message.header.ancount += add_an_len
                resp_message.answer.extend(cname_msg.answer)
                return resp_message.encode_bytes()
            else:
                raise 'error! no cname for final select'
        authority_domain_name = []
        if len(resp_message.authority) > 0:
            ips = []
            for rr in resp_message.authority:
                if rr.type == TYPE_A:
                    ips.append(rr.rdata)
                elif rr.type == TYPE_NS:
                    authority_domain_name.append(rr.rdata)
            if len(ips) > 0:
                return self.iterative_query(data, ips)
        if len(resp_message.additional) > 0:
            ips = []
            for rr in resp_message.additional:
                if rr.type == TYPE_A:
                    ips.append(rr.rdata)
            if len(ips) > 0:
                return self.iterative_query(data, ips)
        # no additional section in the reply
        if authority_domain_name:
            # 只问一个
            authority_data = None
            while not authority_data and len(authority_domain_name) > 0:
                try:
                    authority_data = self.iterative_query(
                        self.construct_query(authority_domain_name[0]).encode_bytes(),
                        server_ip_list)
                    if authority_data == None:
                        raise Exception
                except:
                    print(f"Failed to check the ip of {authority_domain_name[0]}, trying another domain.")
                    authority_domain_name = authority_domain_name[1:]
            if not authority_data:
                raise 'No available ip of authority'
            auth_msg = DNSMessage.from_wire(authority_data)
            if len(auth_msg.answer) > 0:  # 找到了auth的ip
                cname = None
                auth_ips = []
                for rr in auth_msg.answer:
                    if rr.type == TYPE_A:
                        auth_ips.append(rr.rdata)
                    elif rr.type == TYPE_CNAME:
                        cname = rr.rdata
                if len(auth_ips) > 0:
                    return self.iterative_query(data, auth_ips)
                # again only cname
                if cname:  # send another request to cname field and get question
                    cname_data = self.iterative_query(self.construct_query(cname).encode_bytes(), self.root_dns_address)
                    cname_msg = DNSMessage.from_wire(cname_data)
                    for rr in cname_msg.answer:
                        if rr.type == TYPE_A:
                            auth_ips.append(rr.rdata)
                    if len(auth_ips) > 0:
                        return self.iterative_query(data, auth_ips)
                    else:
                        raise "can't find auth server ip even in first cname"
                else:
                    raise 'error! no cname and no ip'
            else:
                raise "can't find authority server ip"
        else:
            raise "can't find ip for next setp"

    def construct_query(self, domain_name: str) -> DNSMessage:
        header = DNSHeader(id=0, flag=b'\x00\x00', qdcount=1, ancount=0, nscount=0, arcount=0)
        question = DNSQuestion(qname=domain_name, qtype=1, qclass=1, next_idx=0)
        return DNSMessage(header=header, question=question, answer=[], authority=[], additional=[])


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 9999
    with socketserver.UDPServer((HOST, PORT), MyLocalDNSServerHandler) as server:
        print('The local DNS server is running')
        server.serve_forever()
