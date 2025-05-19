import random
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import time
import matplotlib.pyplot as plt

NUM_SIGN = 5      # 5 podpisów
NUM_VERIFY = 15   # 15 weryfikacji na wybranym podpisie

def ecc_test(message):
    sign_times = []
    signatures = []
    keys = []

    # 5 podpisów
    for _ in range(NUM_SIGN):
        key = ECC.generate(curve='P-256')
        signer = DSS.new(key, 'fips-186-3')
        h = SHA256.new(message)

        start = time.perf_counter()
        signature = signer.sign(h)
        sign_times.append(time.perf_counter() - start)

        keys.append(key)
        signatures.append(signature)

    avg_sign = sum(sign_times) / NUM_SIGN

    # wybieramy np. pierwszy podpis do testu weryfikacji
    key = keys[0]
    verifier = DSS.new(key.public_key(), 'fips-186-3')
    h = SHA256.new(message)
    signature = signatures[0]

    verify_times = []
    for _ in range(NUM_VERIFY):
        start = time.perf_counter()
        verifier.verify(h, signature)
        verify_times.append(time.perf_counter() - start)

    avg_verify = sum(verify_times) / NUM_VERIFY
    return avg_sign, avg_verify

def rsa_test(message):
    sign_times = []
    signatures = []
    keys = []

    for _ in range(NUM_SIGN):
        key = RSA.generate(2048)
        h = SHA256.new(message)

        start = time.perf_counter()
        signature = pkcs1_15.new(key).sign(h)
        sign_times.append(time.perf_counter() - start)

        keys.append(key)
        signatures.append(signature)

    avg_sign = sum(sign_times) / NUM_SIGN

    key = keys[0]
    h = SHA256.new(message)
    signature = signatures[0]
    verify_times = []

    for _ in range(NUM_VERIFY):
        start = time.perf_counter()
        pkcs1_15.new(key.publickey()).verify(h, signature)
        verify_times.append(time.perf_counter() - start)

    avg_verify = sum(verify_times) / NUM_VERIFY
    return avg_sign, avg_verify

# reszta kodu bez zmian
def run_all_tests():
    print("Start testów ECC vs RSA...")

    sizes = [16, 64, 128, 256, 512, 1024, 2048, 4096]
    results = []

    for size in sizes:
        message = get_random_bytes(size)

        ecc_sign, ecc_verify = ecc_test(message)
        rsa_sign, rsa_verify = rsa_test(message)

        print(f"{size}B:")
        print(f"    ECC: sign {ecc_sign:.6f}s, verify {ecc_verify:.6f}s")
        print(f"    RSA: sign {rsa_sign:.6f}s, verify {rsa_verify:.6f}s")

        results.append({
            "size": size,
            "ecc_sign": ecc_sign,
            "ecc_verify": ecc_verify,
            "rsa_sign": rsa_sign,
            "rsa_verify": rsa_verify,
        })

    return results

def plot_results(results):
    sizes = [r["size"] for r in results]

    plt.figure(figsize=(10, 6))
    plt.plot(sizes, [r["ecc_sign"] for r in results], label="ECC sign", marker="o")
    plt.plot(sizes, [r["rsa_sign"] for r in results], label="RSA sign", marker="x")
    plt.title("Czas podpisywania ECC vs RSA")
    plt.xlabel("Rozmiar wiadomości (B)")
    plt.ylabel("Czas (s)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(10, 6))
    plt.plot(sizes, [r["ecc_verify"] for r in results], label="ECC verify", marker="o")
    plt.plot(sizes, [r["rsa_verify"] for r in results], label="RSA verify", marker="x")
    plt.title("Czas weryfikacji podpisu ECC vs RSA")
    plt.xlabel("Rozmiar wiadomości (B)")
    plt.ylabel("Czas (s)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    results = run_all_tests()
    print("\n📊 Generuję wykresy...")
    plot_results(results)
