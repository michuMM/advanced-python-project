import os

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, ECC, ElGamal
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import ChaCha20

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Random.random import getrandbits, randint
from Crypto.Util.number import GCD, inverse

import time
import json

import base64
from fontTools.ttLib.tables.D_S_I_G_ import b64encode

KEY = b'twojklucz16bajt!'  # 16 bajtów = 128-bit AES
DES_KEY = b'8bDESkey'       # 8 bajtów = 64-bit DES
#CHACHA_KEY = get_random_bytes(32) # 256-bit ChaCha20


def pad(msg):
    return msg + (16 - len(msg) % 16) * chr(16 - len(msg) % 16)

def unpad(msg):
    return msg[:-ord(msg[-1])]

def my_pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def my_unpad(data, block_size=16):
    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Niepoprawna długość paddingu.")
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Niepoprawny padding.")
    return data[:-padding_len]

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

    start = time.perf_counter()
    encrypted = cipher.encrypt(message.encode())
    end = time.perf_counter()

    duration = end - start
    print("RSA - czas enkrypcji: ", duration)
    return base64.b64encode(encrypted).decode()

def decrypt_rsa(enc_message):
    with open("private.pem", "rb") as prv_file:
        private_key = RSA.import_key(prv_file.read())
    cipher = PKCS1_OAEP.new(private_key)

    start = time.perf_counter()
    decrypted = cipher.decrypt(base64.b64decode(enc_message))
    end = time.perf_counter()

    duration = end - start
    print("RSA - czas dekrypcji: ", duration)
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

# ---------- ECC ----------
def encrypt_ecc(message):
    # Wczytaj klucz publiczny odbiorcy
    recipient_key = ECC.import_key(open("ecc_public.pem").read())

    # Wygeneruj tymczasowy klucz nadawcy
    sender_key = ECC.generate(curve='P-256')

    # Oblicz wspólny sekret
    shared_secret_point = recipient_key.pointQ * sender_key.d
    shared_secret = int(shared_secret_point.x).to_bytes(32, 'big')

    # Wygeneruj klucz AES przez HKDF
    key = HKDF(shared_secret, 32, b'', SHA256)

    # Szyfruj wiadomość AES
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(my_pad(message.encode()))

    # Zakoduj wiadomość + publiczny klucz nadawcy
    sender_pub_key = sender_key.export_key(format='PEM')
    full_message = base64.b64encode(iv + ct).decode() + "||" + base64.b64encode(sender_pub_key.encode()).decode()

    return full_message

def decrypt_ecc(full_message):
    print("1")
    try:
        enc_b64, sender_pub_key_b64 = full_message.split("||")
    except ValueError:
        raise Exception("Niepoprawny format wiadomości ECC")

    # Dekodowanie
    encrypted_data = base64.b64decode(enc_b64)
    sender_pub_key_pem = base64.b64decode(sender_pub_key_b64).decode()

    # Wczytaj klucze
    private_key = ECC.import_key(open("ecc_private.pem").read())
    sender_key = ECC.import_key(sender_pub_key_pem)

    # Oblicz wspólny sekret
    shared_secret_point = sender_key.pointQ * private_key.d
    shared_secret = int(shared_secret_point.x).to_bytes(32, 'big')

    # AES key
    key = HKDF(shared_secret, 32, b'', SHA256)

    # Odszyfruj
    iv = encrypted_data[:16]
    ct = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ct)
    try:
        result = my_unpad(decrypted).decode()
    except Exception as e:
        print("❌ Błąd przy odpadaniu/dekodowaniu:", str(e))
        raise
    return result
    #return unpad(decrypted).decode()

# ---------- ChaCha20 ----------
def encrypt_chacha20(message: str) -> str:
    key = os.urandom(32)
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(message.encode())
    return b64encode(cipher.nonce + key + ciphertext)

def decrypt_chacha20(enc_msg):
    raw = base64.b64decode(enc_msg)
    nonce = raw[:8]
    key = raw[8:40]
    ciphertext = raw[40:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

# ---------- ElGamal ----------
def load_elgamal_keys():
    with open("elgamal_public.json", "r") as pub_file:
        pub_data = json.load(pub_file)
    with open("elgamal_private.json", "r") as priv_file:
        priv_data = json.load(priv_file)

    pub_key = ElGamal.construct((int(pub_data['p']), int(pub_data['g']), int(pub_data['y'])))
    priv_key = ElGamal.construct((int(priv_data['p']), int(priv_data['g']), int(priv_data['y']), int(priv_data['x'])))
    return pub_key, priv_key

def encrypt_elgamal(message: str) -> str:
    pub_key, _ = load_elgamal_keys()
    p = int(pub_key.p)
    g = int(pub_key.g)
    y = int(pub_key.y)

    m = int.from_bytes(message.encode(), byteorder='big')
    if m >= p:
        raise ValueError("Wiadomość za długa dla tego klucza ElGamal")

    k = randint(1, p - 2)
    while GCD(k, p - 1) != 1:
        k = randint(1, p - 2)

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    cipher_pair = {'c1': c1, 'c2': c2}
    return base64.b64encode(json.dumps(cipher_pair).encode()).decode()

def decrypt_elgamal(enc_msg: str) -> str:
    with open("elgamal_private.json", "r") as f:
        private_key = json.load(f)

    with open("elgamal_public.json", "r") as f:
        public_key = json.load(f)

    p = int(public_key["p"])
    x = int(private_key["x"])

    cipher_pair = json.loads(base64.b64decode(enc_msg).decode())
    c1 = int(cipher_pair['c1'])
    c2 = int(cipher_pair['c2'])

    s = pow(c1, x, p)
    s_inv = pow(s, -1, p)  # Odwrotność modularna
    m = (c2 * s_inv) % p

    # Odzyskaj wiadomość z liczby całkowitej
    msg_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
    return msg_bytes.decode()
