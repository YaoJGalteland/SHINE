import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import ue_algorithm

# Implement the random permutation Pi(N|data) by AES, it maps to an element in the finite group Fp
pi_key = os.urandom(32)  # AES key
iv = os.urandom(16)
permutation = Cipher(algorithms.AES(pi_key), modes.CBC(iv))

# Generate an epoch key
key1 = ue_algorithm.keygen()

# Messages to be encrypted
short_data = b"SHINE"
long_data = b"Implementing the SHINE Schemes"

# Enc
c = ue_algorithm.enc(key1, short_data, permutation)
c_ocb = ue_algorithm.ocb_enc(key1, long_data, pi_key, permutation)  # OCBSHINE

# Dec
result = ue_algorithm.dec(key1, c, permutation)
result_ocb = ue_algorithm.ocb_dec(key1, c_ocb, pi_key, permutation)  # OCBSHINE
print('Decryption output of fresh encryption:', result_ocb)

# Generate a new epoch key and update token
key2 = ue_algorithm.keygen()
token = ue_algorithm.tokengen(key1, key2)

# Update ciphertext from the old epoch key to the new epoch key
c_new = ue_algorithm.upd(token, c)
c_ocb_new = ue_algorithm.ocb_upd(token, c_ocb)  # OCBSHINE

# Decrypt the updated ciphertext
result2 = ue_algorithm.dec(key2, c_new, permutation)
result2_ocb = ue_algorithm.ocb_dec(key2, c_ocb_new, pi_key, permutation)  # OCBSHINE
print('Decryption output of updated ciphertext:', result2_ocb)

'''#Testing the running time
import time
dur_shine_enc = 0
dur_ocbshine_enc = 0
dur_shine_upd = 0
dur_ocbshine_upd = 0
num_experiment = 10

for i in range(num_experiment):
    start_shine_enc = time.time()
    c = ue_algorithm.enc(key1, short_data, permutation)
    end_shine_enc = time.time()
    dur_shine_enc = dur_shine_enc + end_shine_enc - start_shine_enc
    start_ocbshine_enc = time.time()
    c_ocb = ue_algorithm.ocb_enc(key1, long_data, pi_key, permutation)  # OCBSHINE
    end_ocbshine_enc = time.time()
    dur_ocbshine_enc = dur_ocbshine_enc + end_ocbshine_enc - start_ocbshine_enc

    start_shine_upd = time.time()
    c_new = ue_algorithm.upd(token, c)
    end_shine_upd = time.time()
    start_ocbshine_upd = time.time()
    c_ocb_new = ue_algorithm.ocb_upd(token, c_ocb)  # OCBSHINE
    end_ocbshine_upd = time.time()
    dur_shine_upd = dur_shine_upd + end_shine_upd - start_shine_upd
    dur_ocbshine_upd = dur_ocbshine_upd + end_ocbshine_upd - start_ocbshine_upd

print('shineenc', dur_shine_enc / num_experiment)
print('ocbshineenc', dur_ocbshine_enc / num_experiment)

print('shineupd', dur_shine_upd / num_experiment)
print('ocbshineupd', dur_ocbshine_upd / num_experiment)
'''