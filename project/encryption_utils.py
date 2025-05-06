from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import base64

KEY = b'twojklucz16bajt!'  # 16 bajtów = 128-bit AES
DES_KEY = b'8bDESkey'       # 8 bajtów = 64-bit DES


def pad(msg):
    return msg + (16 - len(msg) % 16) * chr(16 - len(msg) % 16)

def unpad(msg):
    return msg[:-ord(msg[-1])]

# ---------- AES ----------
def encrypt_aes(msg):
    print("DŁUGOSC KLUCZA: ",len(KEY))
    iv = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(msg).encode())
    return base64.b64encode(iv + ct_bytes).decode()

def decrypt_aes(enc_msg):
    raw = base64.b64decode(enc_msg)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct).decode())

# ---------- RSA ----------
def encrypt_rsa(message):
    with open("public.pem", "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_rsa(enc_message):
    with open("private.pem", "rb") as prv_file:
        private_key = RSA.import_key(prv_file.read())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(base64.b64decode(enc_message))
    return decrypted.decode()

# ---------- DES ----------
def encrypt_des(msg):
    iv = get_random_bytes(8)
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(msg).encode())
    return base64.b64encode(iv + ct_bytes).decode()

def decrypt_des(enc_msg):
    raw = base64.b64decode(enc_msg)
    iv = raw[:8]
    ct = raw[8:]
    cipher = DES.new(DES_KEY, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct).decode())