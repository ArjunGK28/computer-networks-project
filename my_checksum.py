import struct 

def checksum(data):
    s = 0

    for i in range(0, len(data) - 1, 2): 
        word = data[i]<<8 + data[i+1] #data[i] is the first byte therefore left shift by 8 and then add data[i+1], which is the second byte, to the last 8 bits
        print(f"  i={i}: bytes ({data[i]}, {data[i+1]}) → word={hex(word)} → running sum={hex(s + word)}")
        s+=word
        

    if len(data)%2 != 0 : 
        s += data[-1] << 8 #if odd number of bytes add the last byte manually
    
    while s >> 16: 
        s = (s & 0xFFFF) + (s >> 16) #we do 0XFFFF to eliminate(zero out) all the top non-16-bit bits
    result = ~s & 0xFFFF

    print(f"  Final sum={hex(s)}, after flip={hex(result)}")
    return result

# test_data = b'\x08\x00\x00\x00\x00\x01\x00\x01'
# checksum(test_data)

test_data_1 = b'\xff\xff\xff\xff\xff\xff\xff\xff'
checksum(test_data_1)