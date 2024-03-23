message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
message = bytearray(message, "utf-8")

while (len(message) * 8) % 512 != 448:
    print("check...")
    message.append(0x00)

print("message:", message)
