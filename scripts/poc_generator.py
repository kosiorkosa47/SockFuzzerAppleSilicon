#!/usr/bin/env python3
# Copyright 2024 ckosiorkosa47
# SPDX-License-Identifier: Apache-2.0
#
# Translate a SockFuzzer crash artifact into a standalone C proof-of-concept.
#
# Usage:
#   python3 scripts/poc_generator.py <crash_file> [output.c]
#
# The crash file is a protobuf-encoded Session message. This script
# decodes it and generates equivalent userspace C syscalls.
#
# Requirements:
#   pip install protobuf
#   Ensure net_fuzzer_pb2.py is generated (run: protoc --python_out=. fuzz/net_fuzzer.proto)

import sys
import os
import struct
from datetime import datetime

DOMAIN_MAP = {
    0: "AF_UNSPEC", 1: "AF_UNIX", 2: "AF_INET", 17: "AF_ROUTE",
    30: "AF_INET6", 32: "AF_SYSTEM", 39: "AF_MULTIPATH",
}

SOCKTYPE_MAP = {
    1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW",
    4: "SOCK_RDM", 5: "SOCK_SEQPACKET",
}

PROTO_MAP = {
    0: "IPPROTO_IP", 6: "IPPROTO_TCP", 17: "IPPROTO_UDP",
    58: "IPPROTO_ICMPV6",
}


def generate_poc_header(crash_file):
    """Generate the C file header."""
    return f"""/*
 * Proof of Concept — auto-generated from SockFuzzer crash artifact
 *
 * Source: {os.path.basename(crash_file)}
 * Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
 *
 * Build:  cc -o poc poc.c
 * Run:    ./poc
 *
 * WARNING: This PoC may trigger a kernel vulnerability.
 * Only run on test systems or VMs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet6/in6.h>
#include <arpa/inet.h>
#include <errno.h>

#define CHECK(expr) do {{ \\
    if ((expr) < 0) {{ \\
        fprintf(stderr, "  %s: %s\\n", #expr, strerror(errno)); \\
    }} \\
}} while(0)

int main(int argc, char **argv) {{
    printf("SockFuzzer PoC — running...\\n");
    int fd = -1, retval = 0;
    (void)retval;

"""


def generate_poc_footer():
    return """
    printf("PoC completed.\\n");
    return 0;
}
"""


def cmd_to_c(cmd_type, cmd_num):
    """Convert a command type string to a C comment + code stub."""
    lines = []
    lines.append(f"    /* Command {cmd_num}: {cmd_type} */")

    if cmd_type == "socket":
        lines.append("    fd = socket(AF_INET, SOCK_STREAM, 0);")
        lines.append('    printf("  socket() = %d\\n", fd);')
    elif cmd_type == "bind":
        lines.append("    {")
        lines.append("        struct sockaddr_in addr = {0};")
        lines.append("        addr.sin_len = sizeof(addr);")
        lines.append("        addr.sin_family = AF_INET;")
        lines.append("        addr.sin_port = htons(0);")
        lines.append("        addr.sin_addr.s_addr = INADDR_ANY;")
        lines.append("        CHECK(bind(fd, (struct sockaddr *)&addr, sizeof(addr)));")
        lines.append("    }")
    elif cmd_type == "listen":
        lines.append("    CHECK(listen(fd, 5));")
    elif cmd_type == "connect":
        lines.append("    {")
        lines.append("        struct sockaddr_in addr = {0};")
        lines.append("        addr.sin_len = sizeof(addr);")
        lines.append("        addr.sin_family = AF_INET;")
        lines.append("        addr.sin_port = htons(80);")
        lines.append("        addr.sin_addr.s_addr = htonl(0x7f000001);")
        lines.append("        CHECK(connect(fd, (struct sockaddr *)&addr, sizeof(addr)));")
        lines.append("    }")
    elif cmd_type == "close":
        lines.append("    if (fd >= 0) { CHECK(close(fd)); fd = -1; }")
    elif cmd_type == "setsockopt":
        lines.append("    {")
        lines.append("        int optval = 1;")
        lines.append("        CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)));")
        lines.append("    }")
    elif cmd_type == "sendto":
        lines.append('    CHECK(sendto(fd, "FUZZ", 4, 0, NULL, 0));')
    elif cmd_type == "shutdown":
        lines.append("    CHECK(shutdown(fd, SHUT_RDWR));")
    else:
        lines.append(f"    /* TODO: implement {cmd_type} */")

    lines.append("")
    return "\n".join(lines)


def generate_poc_from_raw(crash_file, output_file):
    """Generate a PoC from a raw crash file (without protobuf parsing)."""
    with open(crash_file, "rb") as f:
        data = f.read()

    poc = generate_poc_header(crash_file)
    poc += f"    /* Raw crash data: {len(data)} bytes */\n"
    poc += f"    /* First 32 bytes: {data[:32].hex()} */\n\n"

    # Generate a generic socket stress test based on file size
    poc += "    /* Generic socket stress — adapt based on crash analysis */\n"
    poc += "    for (int i = 0; i < 10; i++) {\n"
    poc += "        fd = socket(AF_INET6, SOCK_STREAM, 0);\n"
    poc += '        printf("  socket() = %d\\n", fd);\n'
    poc += "        if (fd < 0) continue;\n\n"

    poc += "        struct sockaddr_in6 addr = {0};\n"
    poc += "        addr.sin6_len = sizeof(addr);\n"
    poc += "        addr.sin6_family = AF_INET6;\n"
    poc += "        addr.sin6_port = htons(0);\n"
    poc += "        bind(fd, (struct sockaddr *)&addr, sizeof(addr));\n"
    poc += "        listen(fd, 5);\n\n"

    if len(data) > 0:
        hex_data = ", ".join(f"0x{b:02x}" for b in data[:256])
        poc += f"    unsigned char payload[] = {{{hex_data}}};\n"
        poc += f"        send(fd, payload, sizeof(payload), 0);\n"

    poc += "        close(fd);\n"
    poc += "    }\n"

    poc += generate_poc_footer()

    with open(output_file, "w") as f:
        f.write(poc)

    print(f"PoC generated: {output_file}")
    print(f"Build: cc -o poc {output_file}")
    print(f"Run:   ./poc")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <crash_file> [output.c]")
        sys.exit(1)

    crash_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "poc.c"

    if not os.path.exists(crash_file):
        print(f"Error: {crash_file} not found")
        sys.exit(1)

    # Try protobuf parsing first, fall back to raw
    try:
        sys.path.insert(0, "build")
        from net_fuzzer_pb2 import Session
        with open(crash_file, "rb") as f:
            session = Session()
            session.ParseFromString(f.read())

        poc = generate_poc_header(crash_file)
        for i, cmd in enumerate(session.commands):
            cmd_type = cmd.WhichOneof("command")
            if cmd_type:
                poc += cmd_to_c(cmd_type, i)
        poc += generate_poc_footer()

        with open(output_file, "w") as f:
            f.write(poc)

        print(f"PoC generated from protobuf: {output_file}")
        print(f"Commands: {len(session.commands)}")

    except (ImportError, Exception) as e:
        print(f"Protobuf parsing unavailable ({e}), using raw mode")
        generate_poc_from_raw(crash_file, output_file)


if __name__ == "__main__":
    main()
