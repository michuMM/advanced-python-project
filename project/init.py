from Crypto.PublicKey import RSA
import os

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    private_path = os.path.join(os.getcwd(), "private.pem")
    public_path = os.path.join(os.getcwd(), "public.pem")

    with open(private_path, "wb") as prv_file:
        prv_file.write(private_key)
    with open(public_path, "wb") as pub_file:
        pub_file.write(public_key)

    print("Klucze wygenerowane:")
    print("Private:", private_path)
    print("Public:", public_path)

generate_rsa_keys()
