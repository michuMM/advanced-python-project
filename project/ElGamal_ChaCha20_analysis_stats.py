import time
from Crypto.Cipher import ChaCha20
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse, GCD

# ============ ChaCha20 TESTS ============

def test_chacha20_times():
    results = []
    msg_lengths = [16, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]

    for msg_len in msg_lengths:
        message = b"A" * msg_len
        enc_times = []
        dec_times = []

        for _ in range(20):
            key = get_random_bytes(32)
            nonce = get_random_bytes(8)

            start = time.time()
            cipher = ChaCha20.new(key=key, nonce=nonce)
            ciphertext = cipher.encrypt(message)
            enc_times.append(time.time() - start)

            start = time.time()
            cipher = ChaCha20.new(key=key, nonce=nonce)
            decrypted = cipher.decrypt(ciphertext)
            dec_times.append(time.time() - start)

        avg_enc = sum(enc_times) / len(enc_times)
        avg_dec = sum(dec_times) / len(dec_times)

        results.append({
            "alg": "ChaCha20",
            "msg_len": msg_len,
            "enc_time": avg_enc,
            "dec_time": avg_dec
        })
        print(f"    ChaCha20 {msg_len}B: enc {avg_enc:.6f}s, dec {avg_dec:.6f}s")

    return results

# ============ ElGamal TESTS ============

def generate_elgamal_key(bits=2048):
    while True:
        p = getPrime(bits)
        g = random.randint(2, p - 1)
        x = random.randint(1, p - 2)
        y = pow(g, x, p)
        if GCD(x, p-1) == 1:
            break
    return {'p': p, 'g': g, 'x': x, 'y': y}

def elgamal_encrypt(p, g, y, m):
    k = random.randint(1, p - 2)
    a = pow(g, k, p)
    b = (pow(y, k, p) * m) % p
    return a, b

def elgamal_decrypt(p, x, a, b):
    s = pow(a, x, p)
    m = (b * inverse(s, p)) % p
    return m

def test_elgamal_times():
    key_sizes = [512, 1024, 2048]
    results = []

    for key_size in key_sizes:
        print(f"\n🔑 ElGamal {key_size}-bit key:")

        start = time.time()
        keys = generate_elgamal_key(key_size)
        end = time.time()
        gen_time = end - start
        print(f"  Czas generowania klucza: {gen_time:.6f} s")

        msg_lengths = [1, 2, 4, 8, 16, 32, 64]  # małe wiadomości (jako liczby)
        for msg_len in msg_lengths:
            message = int.from_bytes(b"A" * msg_len, "big") % keys['p']
            enc_times = []
            dec_times = []

            for _ in range(10):
                start = time.time()
                a, b = elgamal_encrypt(keys['p'], keys['g'], keys['y'], message)
                enc_times.append(time.time() - start)

                start = time.time()
                decrypted = elgamal_decrypt(keys['p'], keys['x'], a, b)
                dec_times.append(time.time() - start)

            avg_enc = sum(enc_times) / len(enc_times)
            avg_dec = sum(dec_times) / len(dec_times)

            results.append({
                "alg": "ElGamal",
                "key_len": key_size,
                "msg_len": msg_len,
                "gen_time": gen_time,
                "enc_time": avg_enc,
                "dec_time": avg_dec
            })
            print(f"    {msg_len}B: enc {avg_enc:.6f}s, dec {avg_dec:.6f}s")

    return results

def plot_additional_results(chacha_data, elgamal_data):
    import matplotlib.pyplot as plt

    # CHACHA20
    plt.figure(figsize=(10, 6))
    x = [r["msg_len"] for r in chacha_data]
    y_enc = [r["enc_time"] for r in chacha_data]
    y_dec = [r["dec_time"] for r in chacha_data]
    plt.plot(x, y_enc, label="ChaCha20 enc", marker='o')
    plt.plot(x, y_dec, label="ChaCha20 dec", marker='x')
    plt.xlabel("Długość wiadomości (B)")
    plt.ylabel("Czas (s)")
    plt.title("ChaCha20: Czas szyfrowania / deszyfrowania")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

    # ELGAMAL
    plt.figure(figsize=(10, 6))
    for key_len in sorted(set(r["key_len"] for r in elgamal_data)):
        subset = [r for r in elgamal_data if r["key_len"] == key_len]
        x = [r["msg_len"] for r in subset]
        y_enc = [r["enc_time"] for r in subset]
        y_dec = [r["dec_time"] for r in subset]
        plt.plot(x, y_enc, label=f'ElGamal {key_len} enc', marker='o')
        plt.plot(x, y_dec, label=f'ElGamal {key_len} dec', marker='x')

    plt.xlabel("Długość wiadomości (B)")
    plt.ylabel("Czas (s)")
    plt.title("ElGamal: Czas szyfrowania / deszyfrowania")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    print("⏱ Start testów ChaCha20...")
    chacha_data = test_chacha20_times()

    print("\n⏱ Start testów ElGamal...")
    elgamal_data = test_elgamal_times()

    print("\n📊 Generuję wykresy...")
    plot_additional_results(chacha_data, elgamal_data)
