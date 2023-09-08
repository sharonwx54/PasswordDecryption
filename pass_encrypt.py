from array import *
import hashlib
import base64
import binascii

# Boilerplate code for breaking password encryption.

# For example, if the username is 'Alice', and she uses 'helloworld' as her 
# password. The password encryption software will record her encrypted password 
# as OUTPUT, where OUTPUT is computed as follows.
username = b'Alice'
password = b'helloworld'

# global salt and mask used for the whole software.
salt = b'blockchains'
mask = b'foundation'

# The input to the hash function is the username concatenated with the salt.
hash_input = username+salt
print("hash_input")
print(hash_input)
print(binascii.hexlify(hash_input)) # unhexlify exist as reverse path

# Compute the SHA256 hash on the hash_input. 
# The resulting digest is a 'bytes' object of size 32 bytes. 
digest_1 = hashlib.sha256(hash_input).digest()
print("digest_1")
print(digest_1)
print(binascii.hexlify(digest_1))

# Compute the SHA256 hash on the mask. 
# The resulting digest is a 'bytes' object of size 32 bytes. 
digest_2 = hashlib.sha256(mask).digest()
print("digest_2")
print(digest_2)
print(binascii.hexlify(digest_2))

# Pad the password such the resulting value is of size 32 bytes.
padded_password = password + bytes(32-len(password))
print("padded_password")
print(padded_password)
print(binascii.hexlify(padded_password))

# Compute encrypted_password = padded_password XOR digest.
encrypted_password = bytes(a ^ b ^ c for a, b, c in zip(padded_password, digest_1, digest_2))
print("encrypted_password")
print(encrypted_password)
print(binascii.hexlify(encrypted_password))

# The software stores the base 64 encoding of the encrypted_password.
OUTPUT = base64.b64encode(encrypted_password).decode()
print("OUTPUT")
print(OUTPUT)
