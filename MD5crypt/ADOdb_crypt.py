import base64
import hashlib
import random


# encrypt_key = "Manzarina"
def keyED(txt: bytes, encrypt_key: str) -> bytes:
    # md5 devuelve bytes en hex, pero en PHP queda en string hexa (32 chars)
    encrypt_key = hashlib.md5(encrypt_key.encode()).hexdigest()
    encrypt_key_bytes = encrypt_key.encode("utf-8")
    # encrypt_key = [0x13, 0x37, 0x61, 0x33, 0x32, 0x62, ...] 32 chars
    tmp = bytearray()
    ctr = 0
    # txt = [0x35, 0x46^0x35, 0x37, 0x52^0x37, 0x61, 0x4f^0x61, 0x33, 0x4d^0x33, ...]
    for b in txt:
        if ctr == len(encrypt_key_bytes):
            ctr = 0
        tmp.append(b ^ encrypt_key_bytes[ctr])
        ctr += 1
    # tmp = [0x35^0x13, (0x46^0x35)^0x37, 0x37^0x61, (0x52^0x37)^0x33, ...]
    return bytes(tmp)

    # diegooleiarz@hotmail.com
    # [0x13^0x46^0x37, 0x61^0x52^0x33, ...]
    # result = [0x13^0x37, 0x61^0x33, ...]


# a = FROM
# [F, R, O, M]

# Capa interna

# a = [F, R, O, M]
# a' = [0-9/a-f*32] = [5,7,a,3,2,b,...] (clave interna)
#
# [a'^b', b^a'^b', b'^b'', b^b'^b'', ...]


# a = texto_conocido[0]
# a' = clave_interna'[0]
# a'' = clave_externa[0]
# [a'^a'', a^a'^a'', b'^b'', b^b'^b'', ...]
def Encrypt(txt: str, key: str) -> str:
    # generar "encrypt_key" como md5(rand(0,32000))
    rand_num = random.randint(0, 32000)
    encrypt_key = hashlib.md5(
        str(rand_num).encode()
    ).hexdigest()  # 32 chars hex 0-9a-f

    tmp = bytearray()
    ctr = 0
    encrypt_key_bytes = encrypt_key.encode("utf-8")

    # encrypt_key = [5,7,a,3,2,b, c, d, e, 1, 3, ...] 32 chars = [0x35, 0x37, 0x61, 0x33, 0x32, 0x62, ...]
    # ["0x46", "0x52", "0x4f", "0x4d"]  # FROM
    for b in txt.encode("utf-8"):
        if ctr == len(encrypt_key_bytes):
            ctr = 0
        # concatenar: un byte del encrypt_key + (txt_byte XOR encrypt_key_byte)
        tmp.append(encrypt_key_bytes[ctr])
        tmp.append(b ^ encrypt_key_bytes[ctr])
        ctr += 1
    # [0x35, 0x46^0x35, 0x37, 0x52^0x37, 0x61, 0x4f^0x61, 0x33, 0x4d^0x33, ...]

    encrypted = keyED(tmp, key)
    return base64.b64encode(encrypted).decode("utf-8")


def Decrypt(txt: str, key: str) -> str:
    # Primero decodificar base64 y aplicar keyED
    decoded = base64.b64decode(txt)
    decoded = keyED(decoded, key)

    tmp = bytearray()
    i = 0
    while i < len(decoded):
        md5_char = decoded[i]
        i += 1
        if i < len(decoded):
            tmp.append(decoded[i] ^ md5_char)
            i += 1
    return tmp.decode("utf-8", errors="ignore")


# Ejemplo de uso
if __name__ == "__main__":
    key = "0123456789abcdef0123456789abcdef"
    original_text = "TO:diegooleiarz@hotmail.com12345"
    encrypted = Encrypt(original_text, key)
    print("Texto original:", original_text)
    print("Texto cifrado:", encrypted)

    decrypted = Decrypt(encrypted, key)
    print("Texto descifrado:", decrypted)
