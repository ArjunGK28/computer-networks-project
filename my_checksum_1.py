import struct

# struct.pack(format, value1, value2, ...)
# "!" means network byte order (always use this for networking)
# "B" means one byte (0-255)
# "H" means two bytes (0-65535)

# Let's pack the number 8 into one byte
one_byte = struct.pack("!B", 8)
print("8 as one byte:", one_byte)          # b'\x08'
print("Length:", len(one_byte), "byte")   # 1

# Pack two numbers into two bytes each
two_shorts = struct.pack("!HH", 1000, 2000)
print("Two shorts:", two_shorts)           # 4 bytes total
print("Length:", len(two_shorts), "bytes") # 4

# Unpack — go from bytes BACK to Python numbers
numbers = struct.unpack("!HH", two_shorts)
print("Unpacked:", numbers)               # (1000, 2000)