<div align="center">

# Local DNS Server: CS305 Programming Assignment

[中文](#项目介绍) / [English](#project-introduction)

南方科技大学 2024 春季 `CS305 计算机网络`编程作业：**本地 DNS 服务器**

使用 Python 实现 DNS 报文解析与构造，并通过迭代查询解析域名。

A local DNS server written in Python that parses and constructs DNS messages and resolves domains through iterative queries.

</div>

## 项目介绍

作业要求实现一个监听 `127.0.0.1:9999` 的本地 DNS 服务器。服务器接收客户端的查询，从根域名服务器开始，依据返回的转介信息逐级查询，最终将结果返回客户端。题目不允许使用专门解析 DNS 报文的第三方库。

## 项目结构

```text
DNS_Server_CS305_Project
├── Code/
│   ├── local_dns_server.py  # DNS 报文处理与服务器实现
│   ├── test.py              # 题目提供的测试
│   ├── my_test.py           # 补充测试
│   ├── ipv6_test.py         # IPv6 相关测试
│   ├── raw_packet/          # 测试用原始 DNS 报文
│   └── README.md            # 原始作业说明
├── Docs/                    # 作业文档与项目报告
├── Publication/             # 项目发布资料
└── README.md
```

## 核心思路

- **报文处理**：将 DNS 报文拆分为头部、问题和资源记录，手动解析和编码各字段，包括域名压缩指针；对 A、AAAA、NS 和 CNAME 记录进行专门处理。
- **迭代查询**：通过 UDP 向根服务器发起查询，根据响应中的 NS 记录和附加的 IPv4 地址继续查询；缺少地址时，先查询域名服务器的地址。
- **别名处理**：遇到仅包含 CNAME 的答案时，继续查询别名指向的域名，并将得到的答案合并到响应中。
- **返回结果**：将查询结果编码为 DNS 响应，发送给原客户端；上游服务器连接超时后尝试列表中的其他地址。

具体题目要求见 [作业说明](Code/README.md)，实现细节见 [项目报告](Docs/Report/12212230_黄政东_报告%5B中文%5D.pdf)。

## Project Introduction

This assignment implements a local DNS server listening on `127.0.0.1:9999`. Starting with a root server, it follows referrals to resolve a client's query and returns the result. The assignment prohibits third-party libraries designed specifically for DNS packet parsing.

## Project Structure

```text
DNS_Server_CS305_Project
├── Code/
│   ├── local_dns_server.py  # DNS message handling and server implementation
│   ├── test.py              # Tests provided with the assignment
│   ├── my_test.py           # Additional tests
│   ├── ipv6_test.py         # IPv6 tests
│   ├── raw_packet/          # Sample DNS packets for testing
│   └── README.md            # Original assignment instructions
├── Docs/                    # Assignment documents and project reports
├── Publication/             # Publication materials
└── README.md
```

## Core Approach

- **Message handling:** Parse and encode DNS headers, questions, and resource records manually, including compressed domain names. A, AAAA, NS, and CNAME records receive type-specific handling.
- **Iterative resolution:** Query a root server over UDP and follow NS referrals using IPv4 addresses in the response. If no address is provided, resolve the name server's address first.
- **Aliases:** When an answer contains only a CNAME, query its target and merge the resulting answers into the response.
- **Response:** Encode and return the result to the client. If an upstream server times out, try another address from the list.

See the [assignment instructions](Code/README.md) for the requirements and the [project report](Docs/Report/12212230_HuangZhengdong_report.pdf) for implementation details.
