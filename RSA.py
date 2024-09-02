import random
import hashlib
import os

# Função para gerar um número primo gde 1024 bits
def generate_large_prime(bits=1024):
  while True:
    num = random.getrandbits(bits)
    if is_prime(num):
      return num

# Teste de primalidade usando o método de Miller-Rabin
def is_prime(n, k=5):  # número de iterações do teste
  if n <= 1 or n == 4:
    return False
  if n <= 3:
    return True
  d = n - 1
  while d % 2 == 0:
    d //= 2
  for _ in range(k):
    if not miller_rabin_test(d, n):
      return False
  return True

def miller_rabin_test(d, n):
  a = 2 + random.randint(1, n - 4)
  x = pow(a, d, n)
  if x == 1 or x == n - 1:
    return True
  while d != n - 1:
    x = (x * x) % n
    d *= 2
    if x == 1:
      return False
    if x == n - 1:
      return True
  return False

# Função para encontrar o inverso modular
def mod_inverse(e, phi):
  g, x, _ = extended_gcd(e, phi)
  if g != 1:
    raise ValueError('O inverso modular não existe')
  else:
    return x % phi

def extended_gcd(a, b):
  if a == 0:
    return b, 0, 1
  gcd, x1, y1 = extended_gcd(b % a, a)
  x = y1 - (b // a) * x1
  y = x1
  return gcd, x, y

# Geração de chaves RSA
def generate_keys(bits=1024):
  p = generate_large_prime(bits)
  q = generate_large_prime(bits)
  n = p * q
  phi = (p - 1) * (q - 1)
  e = 65537  # valor comum para e
  d = mod_inverse(e, phi)
  return (n, e), (n, d)

# Funções de utilidade
def xor_bytes(a, b):
  return bytes(x ^ y for x, y in zip(a, b))

def mgf1(seed, length, hash_function=hashlib.sha256):
  counter = 0
  output = b""
  while len(output) < length:
    C = counter.to_bytes(4, byteorder='big')
    output += hash_function(seed + C).digest()
    counter += 1
  return output[:length]

# Função OAEP de codificação (padding)
def oaep_encode(message, k, hash_function=hashlib.sha256):
  m_len = len(message)
  h_len = hash_function().digest_size
  ps_len = k - m_len - 2 * h_len - 2
  
  ps = b'\x00' * ps_len
  p_hash = hash_function(b"").digest()
  padded_message = p_hash + ps + b'\x01' + message
  
  seed = os.urandom(h_len)
  db_mask = mgf1(seed, k - h_len - 1, hash_function)
  masked_db = xor_bytes(padded_message, db_mask)
  
  seed_mask = mgf1(masked_db, h_len, hash_function)
  masked_seed = xor_bytes(seed, seed_mask)
  
  return b'\x00' + masked_seed + masked_db

# Função OAEP de decodificação (unpadding)
def oaep_decode(encoded_message, k, hash_function=hashlib.sha256):
  h_len = hash_function().digest_size
  masked_seed = encoded_message[1:h_len+1]
  masked_db = encoded_message[h_len+1:]
  
  seed_mask = mgf1(masked_db, h_len, hash_function)
  seed = xor_bytes(masked_seed, seed_mask)
  
  db_mask = mgf1(seed, k - h_len - 1, hash_function)
  padded_message = xor_bytes(masked_db, db_mask)
  
  p_hash = hash_function(b"").digest()
  if not padded_message.startswith(p_hash):
    raise ValueError("Decoding error")
  
  index = padded_message.find(b'\x01', h_len)
  if index == -1:
    raise ValueError("Decoding error")
  
  return padded_message[index+1:]

# Funções de cifração e decifração RSA com OAEP
def rsa_encrypt_oaep(message, public_key, k, hash_function=hashlib.sha256):
  encoded_message = oaep_encode(message, k, hash_function)
  n, e = public_key
  message_int = int.from_bytes(encoded_message, byteorder='big')
  cipher_int = pow(message_int, e, n)
  cipher_bytes = cipher_int.to_bytes(k, byteorder='big')
  return cipher_bytes

def rsa_decrypt_oaep(cipher_bytes, private_key, k, hash_function=hashlib.sha256):
  n, d = private_key
  cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
  message_int = pow(cipher_int, d, n)
  encoded_message = message_int.to_bytes(k, byteorder='big')
  return oaep_decode(encoded_message, k, hash_function)

# Cálculo do hash da mensagem usando SHA-3
def calculate_hash(message):
  hasher = hashlib.sha3_256()
  hasher.update(message.encode())
  return hasher.digest()

# Assinatura da mensagem
def sign_message(message, private_key):
  message_hash = calculate_hash(message)
  message_hash_int = int.from_bytes(message_hash, byteorder='big')
  n, d = private_key
  signature_int = pow(message_hash_int, d, n)
  return signature_int

# Formatação do resultado em BASE64 (para simplificação, usaremos bytes diretamente)
def format_signature(signature_int):
  return signature_int.to_bytes((signature_int.bit_length() + 7) // 8, byteorder='big')

# Verificação da assinatura
def verify_signature(message, signature_bytes, public_key):
  n, e = public_key
  signature_int = int.from_bytes(signature_bytes, byteorder='big')
  message_hash_int = pow(signature_int, e, n)
  calculated_hash = calculate_hash(message)
  calculated_hash_int = int.from_bytes(calculated_hash, byteorder='big')
  return message_hash_int == calculated_hash_int

if __name__ == "__main__":
  # Geração das chaves
  public_key, private_key = generate_keys(1024)
  k = (public_key[0].bit_length() + 7) // 8  # Tamanho em bytes da chave pública
  
  while(True):
    print("Opções:")
    print("1 - Criptografar um arquivo usando RSA OAEP")
    print("2 - Desencriptar um arquivo usando RSA OAEP")
    print("3 - Fazer a assinatura de um arquivo")
    print("4 - Verificar a assinatura de um arquivo")
    print("5 - Sair")
    print()
    
    escolha = input("Escolha uma opção: ")
    
    if escolha == "1":
      arquivo = input("Digite o nome do arquivo txt sem a extensão: ")
      
      with open(arquivo + ".txt", 'rb') as file:
        texto = file.read()
        ciphertext = rsa_encrypt_oaep(texto, public_key, k)
        file.close()
        
      with open(arquivo + "_encriptado.txt", 'wb') as file:
        file.write(ciphertext)
        file.close()

      print(f'Arquivo encriptado com o nome {arquivo}_encriptado.txt\n\n')
      
    elif escolha == "2":
      arquivo = input("Digite o nome do arquivo txt sem a extensão: ")
      
      with open(arquivo + ".txt", 'rb') as file:
        texto = file.read()
        decrypted_message = rsa_decrypt_oaep(texto, private_key, k)
        file.close()
        
      with open(arquivo + "_desencriptado.txt", 'wb') as file:
        file.write(decrypted_message)
        file.close()

      print(f'Arquivo desencriptado com o nome {arquivo}_desencriptado.txt\n\n')
      
    elif escolha == "3":
      arquivo = input("Digite o nome do arquivo txt sem a extensão: ")
      
      with open(arquivo + ".txt", 'rb') as file:
        texto = file.read().decode('utf-8')
        assinatura_int = sign_message(texto, private_key)
        assinatura_bytes = format_signature(assinatura_int)
        file.close()
        
      with open(arquivo + "_assinado.txt", 'wb') as file:
        file.write(assinatura_bytes)
        file.close()
        
      print(f'Arquivo assinado com o nome {arquivo}_assinado.txt\n\n')
      
    elif escolha == "4":
      arquivo_na = input("Digite o nome do arquivo txt original sem a extensão: ")
      arquivo_a = input("Digite o nome do arquivo txt com a assinatura sem a extensão: ")
      
      with open(arquivo_na + ".txt", 'rb') as file:
        texto = file.read().decode('utf-8')
        file.close()
        
      with open(arquivo_a + ".txt", 'rb') as file:
        texto_assinado = file.read()
        file.close()
      
      if verify_signature(texto, texto_assinado, public_key):
        print("Assinatura verificada com sucesso!\n\n")
      else:
        print("Assinatura inválida!\n\n")
      
    elif escolha == "5":
      break
    
    else:
      print("Comando inválido!!\n\n")