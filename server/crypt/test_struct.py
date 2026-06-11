import timeit
import struct

data = b"A" * 40 + b"\x00\x00\x03\xe8" + b"B" * 56

def via_slice():
    chunk = data[40:44]
    return int.from_bytes(chunk, byteorder="big")

compiled_struct = struct.Struct(">40xI")
def via_struct():
    return compiled_struct.unpack_from(data)[0]

print("Срез + int.from_bytes:", timeit.timeit(via_slice, number=5_000_000), "сек")
print("Предкомпилированный struct:", timeit.timeit(via_struct, number=5_000_000), "сек")