import json
from Crypto.PublicKey import RSA, ECC, ElGamal
from Crypto import Random
import os

def generate_rsa_keys():
    private_path = os.path.join(os.getcwd(), "private.pem")
    public_path = os.path.join(os.getcwd(), "public.pem")

    if os.path.exists(private_path) and os.path.exists(public_path):
        print("Klucze RSA już istnieją. Pomijanie generowania.")
        return

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_path, "wb") as prv_file:
        prv_file.write(private_key)
    with open(public_path, "wb") as pub_file:
        pub_file.write(public_key)

    print("Klucze wygenerowane:")
    print("Private:", private_path)
    print("Public:", public_path)


def generate_ecc_keys():
    ecc_private_path = os.path.join(os.getcwd(), "ecc_private.pem")
    ecc_public_path = os.path.join(os.getcwd(), "ecc_public.pem")

    if os.path.exists(ecc_private_path) or os.path.exists(ecc_public_path):
        response = input("Klucze ECC już istnieją. Czy chcesz je nadpisać? (t/n): ")
        if response.lower() != 't':
            print("Pomijanie generowania kluczy ECC.")
            return

    key = ECC.generate(curve="P-256")
    private_key = key.export_key(format="PEM")
    public_key = key.public_key().export_key(format="PEM")

    with open(ecc_private_path, "wt") as prv_file:
        prv_file.write(private_key)
    with open(ecc_public_path, "wt") as pub_file:
        pub_file.write(public_key)

    print("Klucze ECC wygenerowane:")
    print("Private:", ecc_private_path)
    print("Public:", ecc_public_path)

def save_elgamal_private_key(key, filename):
    data = {
        'p': int(key.p),
        'g': int(key.g),
        'y': int(key.y),
        'x': int(key.x)
    }
    with open(filename, 'w') as f:
        json.dump(data, f)

def save_elgamal_public_key(key, filename):
    data = {
        'p': int(key.p),
        'g': int(key.g),
        'y': int(key.y)
    }
    with open(filename, 'w') as f:
        json.dump(data, f)

def generate_elgamal_keys():
    elgamal_private_path = os.path.join(os.getcwd(), "elgamal_private.json")
    elgamal_public_path = os.path.join(os.getcwd(), "elgamal_public.json")

    if os.path.exists(elgamal_private_path) and os.path.exists(elgamal_public_path):
        response = input("Klucze ElGamal już istnieją. Czy chcesz je nadpisać? (t/n): ")
        if response.lower() != 't':
            print("Pomijanie generowania kluczy ElGamal.")
            return

    key = ElGamal.generate(256, Random.new().read)  # 256-bit długość klucza - możesz zwiększyć

    save_elgamal_private_key(key, elgamal_private_path)
    save_elgamal_public_key(key, elgamal_public_path)

    print("Klucze ElGamal wygenerowane:")
    print("Private:", elgamal_private_path)
    print("Public:", elgamal_public_path)


if __name__ == "__main__":
    generate_rsa_keys()
    generate_ecc_keys()
    generate_elgamal_keys()