from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# key generation Alisa
privatekey = RSA.generate(2048)
f = open('alisaprivatekey.txt','wb')
f.write(bytes(privatekey.exportKey('PEM'))); f.close()
publickey = privatekey.publickey()
f = open('alisapublickey.txt','wb')
f.write(bytes(publickey.exportKey('PEM'))); f.close()
# key generation Bob
privatekey = RSA.generate(2048)
f = open('bobprivatekey.txt','wb')
f.write(bytes(privatekey.exportKey('PEM'))); f.close()
publickey = privatekey.publickey()
f = open('bobpublickey.txt','wb')
f.write(bytes(publickey.exportKey('PEM'))); f.close()

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# creation of signature
f = open('plaintext.txt','rb')
plaintext = f.read(); f.close()
privatekey = RSA.importKey(open('alisaprivatekey.txt','rb').read())
myhash = SHA.new(plaintext)
signature = PKCS1_v1_5.new(privatekey)
signature = signature.sign(myhash)
# signature encrypt
publickey = RSA.importKey(open('bobpublickey.txt','rb').read())
cipherrsa = PKCS1_OAEP.new(publickey)
sig = cipherrsa.encrypt(signature[:128])
sig = sig + cipherrsa.encrypt(signature[128:])
f = open('signature.txt','wb')
f.write(bytes(sig)); f.close()

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# creation 256 bit session key 
sessionkey = Random.new().read(32) # 256 bit
# encryption AES of the message
f = open('plaintext.txt','rb')
plaintext = f.read(); f.close()
iv = Random.new().read(16) # 128 bit
obj = AES.new(sessionkey, AES.MODE_CFB, iv)
ciphertext = iv + obj.encrypt(plaintext)
f = open('msg.txt','wb')
f.write(bytes(ciphertext)); f.close()
# encryption RSA of the session key
publickey = RSA.importKey(open('bobpublickey.txt','rb').read())
cipherrsa = PKCS1_OAEP.new(publickey)
sessionkey = cipherrsa.encrypt(sessionkey)
f = open('sessionkey.txt','wb')
f.write(bytes(sessionkey)); f.close()

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# decryption session key
privatekey = RSA.importKey(open('bobprivatekey.txt','rb').read())
cipherrsa = PKCS1_OAEP.new(privatekey)
f = open('sessionkey.txt','rb')
sessionkey = f.read(); f.close()
sessionkey = cipherrsa.decrypt(sessionkey)
# decryption message
f = open('msg.txt','rb')
ciphertext = f.read(); f.close()
iv = ciphertext[:16]
obj = AES.new(sessionkey, AES.MODE_CFB, iv)
plaintext = obj.decrypt(ciphertext)
plaintext = plaintext[16:]
f = open('plaintext.txt','wb')
f.write(bytes(plaintext)); f.close()

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# decryption signature
f = open('signature.txt','rb')
signature = f.read(); f.close()
privatekey = RSA.importKey(open('bobprivatekey.txt','rb').read())
cipherrsa = PKCS1_OAEP.new(privatekey)
sig = cipherrsa.decrypt(signature[:256])
sig = sig + cipherrsa.decrypt(signature[256:])
# signature verification
f = open('msg.txt','rb')
plaintext = f.read(); f.close()
publickey = RSA.importKey(open('alisapublickey.txt','rb').read())
myhash = SHA.new(plaintext)
signature = PKCS1_v1_5.new(publickey)
test = signature.verify(myhash, sig)


### ETO BRED

