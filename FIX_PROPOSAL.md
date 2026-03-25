To create a crash-to-PoC automatic translator, we'll need to write a Python script that can parse the protobuf binary, translate the commands, and generate a C file. Here's a step-by-step solution:

### Step 1: Install Required Libraries

First, install the required libraries using pip:
```bash
pip install protobuf
```
### Step 2: Parse Crash Protobuf Binary

Create a Python script `poc_generator.py` and add the following code to parse the crash protobuf binary:
```python
import sys
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2

# Load the protobuf descriptor
with open('sockfuzzer.proto', 'rb') as f:
    descriptor_data = f.read()
descriptor = _descriptor.FileDescriptor(
    name='sockfuzzer.proto',
    package='sockfuzzer',
    syntax='proto3',
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
    serialized_pb=descriptor_data,
    serialized_pb_with_type=None,
    dependencies=[],
    public_dependencies=[],
    extension_ranges=[],
    oneofs=[],
    serialized_start=0,
    serialized_end=155,
)

# Parse the crash protobuf binary
def parse_crash_file(crash_file):
    with open(crash_file, 'rb') as f:
        crash_data = f.read()
    session = _reflection.ParseMessage(descriptor, crash_data)
    return session
```
### Step 3: Translate Commands and Generate C File

Add the following code to translate the commands and generate a C file:
```python
import os

# Translate commands and generate C file
def generate_poc(session, output_file):
    with open(output_file, 'w') as f:
        f.write('#include <stdio.h>\n')
        f.write('#include <stdlib.h>\n')
        f.write('#include <sys/socket.h>\n')
        f.write('#include <netinet/in.h>\n')
        f.write('#include <arpa/inet.h>\n\n')

        for command in session.commands:
            if command.type == 'CREATE_SOCKET':
                f.write(f'int sock = socket({command.domain}, {command.type}, {command.protocol});\n')
            elif command.type == 'BIND':
                f.write(f'bind(sock, (struct sockaddr *)&{command.addr}, {command.addrlen});\n')
            elif command.type == 'LISTEN':
                f.write(f'listen(sock, {command.backlog});\n')
            elif command.type == 'ACCEPT':
                f.write(f'int new_sock = accept(sock, NULL, NULL);\n')
            elif command.type == 'CONNECT':
                f.write(f'connect(sock, (struct sockaddr *)&{command.addr}, {command.addrlen});\n')
            elif command.type == 'SEND':
                f.write(f'send(sock, {command.buf}, {command.len}, 0);\n')
            elif command.type == 'RECV':
                f.write(f'recv(sock, {command.buf}, {command.len}, 0);\n')
            elif command.type == 'CLOSE':
                f.write(f'close(sock);\n')

        f.write('\nint main() {\n')
        f.write('    // Initialize socket\n')
        f.write('    int sock = socket(AF_INET, SOCK_STREAM, 0);\n')
        f.write('    if (sock < 0) {\n')
        f.write('        perror("socket");\n')
        f.write('        return 1;\n')
        f.write('    }\n\n')

        for command in session.commands:
            if command.type == 'CREATE_SOCKET':
                f.write(f'    // Create socket\n')
                f.write(f'    int sock = socket({command.domain}, {command.type}, {command.protocol});\n')
                f.write('    if (sock < 0) {\n')
                f.write('        perror("socket");\n')
                f.write('        return 1;\n')
                f.write('    }\n\n')

        f.write('    return 0;\n')
        f.write('}\n')

# Usage
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python poc_generator.py <crash_file> <output_file>')
        sys.exit(1)

    crash_file = sys.argv[1]
    output_file = sys.argv[2]

    session = parse_crash_file(crash_file)
    generate_poc(session, output_file)
```
### Step 4: Add Verify Step

Add the following code to verify the generated PoC:
```python
import subprocess

# Verify the generated PoC
def verify_poc(output_file):
    try:
        subprocess.check_output(['gcc', '-o', 'poc', output_file])
        subprocess.check_output(['./poc'])
    except subprocess.CalledProcessError as e:
        print(f'Verification failed: {e}')
        return False
    return True

# Usage
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python poc_generator.py <crash_file> <output_file>')
        sys.exit(1)

    crash_file = sys.argv[1]
    output_file = sys.argv[2]

    session = parse_crash_file(crash_file)
    generate_poc(session, output_file)
    if verify_poc(output_file):
        print('Verification successful')
    else:
        print('Verification failed')
```
### Step 5: Add Header Comments

Add the following code to add header comments:
```python
# Add header comments
def add_header_comments(output_file):
    with open(output_file, 'r') as f:
        lines = f.readlines()

    with open(output_file, 'w') as f:
        f.write('// Crash context:\n')
        f.write('//   Crash file: {}\n'.format(crash_file))
        f.write('//   Output file: {}\n'.format(output_file))
        f.write('\n')
        f.writelines(lines)

# Usage
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python poc_generator.py <crash_file> <output_file>')
        sys.exit(1)

    crash_file = sys.argv[1]
    output_file = sys.argv[2]

    session = parse_crash_file(crash_file)
    generate_poc(session, output_file)
    add_header_comments(output_file)
    if verify_poc(output_file):
        print('Verification successful')
    else:
        print('Verification failed')
```
The complete code is:
```python
import sys
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
import os
import subprocess

# Load the protobuf descriptor
with open('sockfuzzer.proto', 'rb') as f:
    descriptor_data = f.read()
descriptor = _descriptor.FileDescriptor(
    name='sockfuzzer.proto',
    package='sockfuzzer',
    syntax='proto3',
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
    serialized_pb=descriptor_data,
    serialized_pb_with_type=None,
    dependencies=[],
    public_dependencies=[],
    extension_ranges=[],
    oneofs=[],
    serialized_start=0,
    serialized_end=155,
)

# Parse the crash protobuf binary
def parse_crash_file(crash_file):
    with open(crash_file, 'rb') as f:
        crash_data = f.read()
    session = _reflection.ParseMessage(descriptor, crash_data)
    return session

# Translate commands and generate C file
def generate_poc(session, output_file):
    with open(output_file, 'w') as f:
        f.write('#include <stdio.h>\n')
        f.write('#include <stdlib.h>\n')
        f.write('#include <sys/socket.h>\n')
        f.write('#include <netinet/in.h>\n')
        f.write('#include <arpa/inet.h>\n\n')

        for command in session.commands:
            if command.type == 'CREATE_SOCKET':
                f.write(f'int sock = socket({command.domain}, {command.type}, {command.protocol});\n')
            elif command.type == 'BIND':
                f.write(f'bind(sock, (struct sockaddr *)&{command.addr}, {command.addrlen});\n')
            elif command.type == 'LISTEN':
                f.write(f'listen(sock, {command.backlog});\n')
            elif command.type == 'ACCEPT':
                f.write(f'int new_sock = accept(sock, NULL, NULL);\n')
            elif command.type == 'CONNECT':
                f.write(f'connect(sock, (struct sockaddr *)&{command.addr}, {command.addrlen});\n')
            elif command.type == 'SEND':
                f.write(f'send(sock, {command.buf}, {command.len}, 0);\n')
            elif command.type == 'RECV':
                f.write(f'recv(sock, {command.buf}, {command.len}, 0);\n')
            elif command.type == 'CLOSE':
                f.write(f'close(sock);\n')

        f.write('\nint main() {\n')
        f.write('    // Initialize socket\n')
        f.write('    int sock = socket(AF_INET, SOCK_STREAM, 0);\n')
        f.write('    if (sock < 0) {\n')
        f.write('        perror("socket");\n')
        f.write('        return 1;\n')
        f.write('    }\n\n')

        for command in session.commands:
            if command.type == 'CREATE_SOCKET':
                f.write(f'    // Create socket\n')
                f.write(f'    int sock = socket({command.domain}, {command.type}, {command.protocol});\n')
                f.write('    if (sock < 0) {\n')
                f.write('        perror("socket");\n')
                f.write('        return 1;\n')
                f.write('    }\n\n')

        f.write('    return 0;\n')
        f.write('}\n')

# Verify the generated PoC
def verify_poc(output_file):
    try:
        subprocess.check_output(['gcc', '-o', 'poc', output_file])
        subprocess.check_output(['./poc'])
    except subprocess.CalledProcessError as e:
        print(f'Verification failed: {e}')
        return False
    return True

# Add header comments
def add_header_comments(output_file, crash_file):
    with open(output_file, 'r') as f:
        lines = f.readlines()

    with open(output_file, 'w') as f:
        f.write('// Crash context:\n')
        f.write('//   Crash file: {}\n'.format(crash_file))
        f.write('//   Output file: {}\n'.format(output_file))
        f.write('\n')
        f.writelines(lines)

# Usage
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python poc_generator.py <crash_file> <output_file>')
        sys.exit(1)

    crash_file = sys.argv[1]
    output_file = sys.argv[2]

    session = parse_crash_file(crash_file)
    generate_poc(session, output_file)
    add_header_comments(output_file, crash_file)
    if verify_poc(output_file):
        print('Verification successful')
    else:
        print('Verification failed')
```
To use the script, save it as `poc_generator.py` and run it with the following command:
```bash
python poc_generator.py <crash_file> <output_file>
```
Replace `<crash_file>` with the path to the crash file and `<output_file>` with the desired output file name. The script will generate a C file that reproduces the bug and verify it by compiling and running it.