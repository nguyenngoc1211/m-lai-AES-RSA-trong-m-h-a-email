# gen_keys.py
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keypair(prefix):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    # private key
    with open(f"{prefix}_priv.pem", "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # public key
    with open(f"{prefix}_pub.pem", "wb") as f:
        f.write(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Generated {prefix}_priv.pem and {prefix}_pub.pem")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate RSA keypair")
    parser.add_argument("prefix", help="Tên prefix cho file PEM")
    args = parser.parse_args()

    generate_keypair(args.prefix)
