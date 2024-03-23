def sha256(message):

    # Constants
    hash_pieces = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]

    k = [
        0x428A2F98,
        0x71374491,
        0xB5C0FBCF,
        0xE9B5DBA5,
        0x3956C25B,
        0x59F111F1,
        0x923F82A4,
        0xAB1C5ED5,
        0xD807AA98,
        0x12835B01,
        0x243185BE,
        0x550C7DC3,
        0x72BE5D74,
        0x80DEB1FE,
        0x9BDC06A7,
        0xC19BF174,
        0xE49B69C1,
        0xEFBE4786,
        0x0FC19DC6,
        0x240CA1CC,
        0x2DE92C6F,
        0x4A7484AA,
        0x5CB0A9DC,
        0x76F988DA,
        0x983E5152,
        0xA831C66D,
        0xB00327C8,
        0xBF597FC7,
        0xC6E00BF3,
        0xD5A79147,
        0x06CA6351,
        0x14292967,
        0x27B70A85,
        0x2E1B2138,
        0x4D2C6DFC,
        0x53380D13,
        0x650A7354,
        0x766A0ABB,
        0x81C2C92E,
        0x92722C85,
        0xA2BFE8A1,
        0xA81A664B,
        0xC24B8B70,
        0xC76C51A3,
        0xD192E819,
        0xD6990624,
        0xF40E3585,
        0x106AA070,
        0x19A4C116,
        0x1E376C08,
        0x2748774C,
        0x34B0BCB5,
        0x391C0CB3,
        0x4ED8AA4A,
        0x5B9CCA4F,
        0x682E6FF3,
        0x748F82EE,
        0x78A5636F,
        0x84C87814,
        0x8CC70208,
        0x90BEFFFA,
        0xA4506CEB,
        0xBEF9A3F7,
        0xC67178F2,
    ]

    # Padding
    original_length = len(message) * 8
    message.append(0x80)
    while (len(message) * 8) % 512 != 448:
        message.append(0x00)
    message += original_length.to_bytes(8, "big")

    # Process the message in 512-bit chunks
    for chunk_start in range(0, len(message), 64):
        chunk = message[chunk_start : chunk_start + 64]

        # Initialize message schedule array
        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i * 4 : i * 4 + 4], "big")
            # print(f"w:{i} : ", w[i])

        # Extend the first 16 words into the remaining 48 words
        for i in range(16, 64):
            s0 = (
                (w[i - 15] >> 7 | w[i - 15] << 25) & 0xFFFFFFFF
                ^ (w[i - 15] >> 18 | w[i - 15] << 14) & 0xFFFFFFFF
                ^ (w[i - 15] >> 3)
            )
            s1 = (
                (w[i - 2] >> 17 | w[i - 2] << 15) & 0xFFFFFFFF
                ^ (w[i - 2] >> 19 | w[i - 2] << 13) & 0xFFFFFFFF
                ^ (w[i - 2] >> 10)
            )
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        # Initialize working variables
        a, b, c, d, e, f, g, h = hash_pieces

        # Compression function main loop
        for i in range(64):
            S1 = (
                (e >> 6 | e << 26) & 0xFFFFFFFF
                ^ (e >> 11 | e << 21) & 0xFFFFFFFF
                ^ (e >> 25 | e << 7) & 0xFFFFFFFF
            )
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + k[i] + w[i]) & 0xFFFFFFFF
            S0 = (
                (a >> 2 | a << 30) & 0xFFFFFFFF
                ^ (a >> 13 | a << 19) & 0xFFFFFFFF
                ^ (a >> 22 | a << 10) & 0xFFFFFFFF
            )
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Add the compressed chunk to the current hash value
        hash_pieces = [
            (x + y) & 0xFFFFFFFF for x, y in zip(hash_pieces, [a, b, c, d, e, f, g, h])
        ]

    # Produce the final hash value (big-endian)
    return "".join(f"{x:08x}" for x in hash_pieces)


message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
message = bytearray(message, "utf-8")
print(f'SHA-256("{message}") = {sha256(message)}')
