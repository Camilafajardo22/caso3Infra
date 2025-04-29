import rsa
import time

num_blocks = 100000 

(public_key, private_key) = rsa.newkeys(2048)

block_data = b"X" * 100 
max_block_size = 256

if len(block_data) > max_block_size:
    print(f"Los datos de entrada superan el tamaño máximo de bloque permitido para RSA ({max_block_size} bytes).")
    block_data = block_data[:max_block_size]

start_time = time.time()

for _ in range(num_blocks):
    encrypted_data = rsa.encrypt(block_data, public_key)

end_time = time.time()

time_taken_rsa = end_time - start_time
operations_per_second_rsa = num_blocks / time_taken_rsa

print(f"Tiempo de cifrado RSA: {time_taken_rsa:.4f} segundos")
print(f"Operaciones de cifrado RSA por segundo: {operations_per_second_rsa:.2f}")
