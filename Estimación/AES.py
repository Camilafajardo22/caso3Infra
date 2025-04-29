from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import time

block_size = 1024 
num_blocks = 100000  
key = get_random_bytes(32) 
cipher = AES.new(key, AES.MODE_CBC)
data = b"X" * block_size

start_time = time.time()

for _ in range(num_blocks):
    cipher.encrypt(pad(data, AES.block_size))

end_time = time.time()

time_taken_aes = end_time - start_time
operations_per_second_aes = num_blocks / time_taken_aes

print(f"Tiempo de cifrado AES: {time_taken_aes:.4f} segundos")
print(f"Operaciones de cifrado AES por segundo: {operations_per_second_aes:.2f}")
