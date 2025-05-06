from Crypto.PublicKey import RSA, ECC
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



if __name__ == "__main__":
    generate_rsa_keys()
    generate_ecc_keys()