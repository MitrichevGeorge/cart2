from cryptography.hazmat.primitives.asymmetric import ed25519

alice_private_key = ed25519.Ed25519PrivateKey.generate()
alice_public_key = alice_private_key.public_key()

message = b"very secret message"
signature = alice_private_key.sign(message)

print(f"Подпись (hex): {signature.hex()}")

try:
    alice_public_key.verify(signature, message)
    print("Успех: Подпись подлинная!")
except Exception:
    print("Ошибка: Подпись неверна или сообщение было изменено!")