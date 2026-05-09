import rsa

(pubkey, privkey) = rsa.newkeys(1024)
message = b'Demo text (pubkey, privkey) = rsa.newkeys(512)(pubkey, privkey) = rsa.newkeys(512)(pubkey, privkey) = rsa.newkeys(512)(pubkey, privkey) = rsa.newkeys(512)(pubkey, privkey) = rsa.newkeys(512)(pubkey, privkey) = rsa.newkeys(512)'

crypto = rsa.encrypt(message, pubkey)
print(crypto)
print("\n")

message = rsa.decrypt(crypto, privkey)
print(message)

#WORK but too stupid and symbol limit
