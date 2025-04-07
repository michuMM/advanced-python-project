from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

KEY = b'twojklucz16bajt!'  # 16 bajtów = 128-bit AES


def pad(msg):
    return msg + (16 - len(msg) % 16) * chr(16 - len(msg) % 16)

def unpad(msg):
    return msg[:-ord(msg[-1])]

def encrypt(msg):
    print("DŁUGOSC KLUCZA: ",len(KEY))
    iv = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(msg).encode())
    return base64.b64encode(iv + ct_bytes).decode()

def decrypt(enc_msg):
    raw = base64.b64decode(enc_msg)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct).decode())
