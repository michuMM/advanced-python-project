from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

import time

import base64

KEY = b'twojklucz16bajt!'  # 16 bajtów = 128-bit AES
DES_KEY = b'8bDESkey'       # 8 bajtów = 64-bit DES


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
