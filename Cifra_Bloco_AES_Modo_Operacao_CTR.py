# Cifra de Bloco AES (Advanced Encryption Standard)
# Modo de Operação CTR (Counter Mode)

# Importação da biblioteca NUMPY
import numpy as np

# SBOX: Componente básico do algoritmo de cifra de bloco AES que realiza substituição de bytes (SubBytes).
SBOX = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# INV-SBOX: Componente inversa do algoritmo de cifra de bloco AES que realiza substituição inversa de bytes (InverseSubBytes).
INV_SBOX = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# RCON: Constantes usadas na expansão da chave (KeyExpansion)
RCON = [
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]

# Substituição de Bytes: Transforma cada byte no bloco através de uma tabela conhecida como S-BOX.
def sub_bytes(state):
  return [SBOX[b] for b in state]

# Substituição Inversa de Bytes: Transforma cada byte no bloco através de uma tabela conhecida como INV-SBOX.
def inv_sub_bytes(state):
  return [INV_SBOX[b] for b in state]

# Deslocamento de Linhas: Rotaciona cada linha da matriz do bloco para esquerda por um número diferente de bytes
def shift_rows(state):
  return [
    state[0], state[5], state[10], state[15],
    state[4], state[9], state[14], state[3],
    state[8], state[13], state[2], state[7],
    state[12], state[1], state[6], state[11]
  ]

# Deslocamento Inverso de Linhas: Rotaciona cada linha da matriz do bloco para direita desfazendo a operação shift rows
def inv_shift_rows(state):
  return [
    state[0], state[13], state[10], state[7],
    state[4], state[1], state[14], state[11],
    state[8], state[5], state[2], state[15],
    state[12], state[9], state[6], state[3]
  ]

# Multiplicação de Galois: Implementa a multiplicação de dois números em um campo finito de Galois, especificamente o campo 𝐺𝐹(2^8).
def gmul(a, b):
  p = 0
  for i in range(8):
    if b & 1:
      p ^= a
    carry = a & 0x80
    a <<= 1
    if carry:
      a ^= 0x1B
    b >>= 1
  return p & 0xFF

# Mistura de Colunas: Mistura os dados de cada coluna na matriz
def mix_columns(state):
  mixed = []
  for i in range(4):
    mixed.append(gmul(state[i], 2) ^ gmul(state[4 + i], 3) ^ state[8 + i] ^ state[12 + i])
    mixed.append(state[i] ^ gmul(state[4 + i], 2) ^ gmul(state[8 + i], 3) ^ state[12 + i])
    mixed.append(state[i] ^ state[4 + i] ^ gmul(state[8 + i], 2) ^ gmul(state[12 + i], 3))
    mixed.append(gmul(state[i], 3) ^ state[4 + i] ^ state[8 + i] ^ gmul(state[12 + i], 2))
  return mixed

# Mistura Inversa de Colunas: Mistura os dados de cada coluna na matriz diferente da MixColumns
def inv_mix_columns(state):
  mixed = []
  for i in range(4):
    mixed.append(gmul(state[i], 0x0e) ^ gmul(state[4 + i], 0x0b) ^ gmul(state[8 + i], 0x0d) ^ gmul(state[12 + i], 0x09))
    mixed.append(gmul(state[i], 0x09) ^ gmul(state[4 + i], 0x0e) ^ gmul(state[8 + i], 0x0b) ^ gmul(state[12 + i], 0x0d))
    mixed.append(gmul(state[i], 0x0d) ^ gmul(state[4 + i], 0x09) ^ gmul(state[8 + i], 0x0e) ^ gmul(state[12 + i], 0x0b))
    mixed.append(gmul(state[i], 0x0b) ^ gmul(state[4 + i], 0x0d) ^ gmul(state[8 + i], 0x09) ^ gmul(state[12 + i], 0x0e))
  return mixed

# Adição da Chave de Rodada: Combina o bloco com uma sub chave gerada a partir da chave original usando uma operação XOR.
def add_round_key(state, key_schedule, round):
  round_key = key_schedule[round * 16:(round + 1) * 16]
  return [state[i] ^ round_key[i] for i in range(16)]

# Expansão da Chave: Gera chaves de rodada a partir da chave inicial de 128 bits para cada uma das 10 rodadas configuráveis do AES-128.
def key_expansion(key):
  key_schedule = list(key)
  for i in range(4, 44):
    temp = key_schedule[(i-1)*4:i*4]
    if i % 4 == 0:
      temp = sub_bytes([temp[1], temp[2], temp[3], temp[0]])
      temp[0] ^= RCON[i//4 - 1]
    key_schedule += [key_schedule[(i-4)*4 + j] ^ temp[j] for j in range(4)]
  return key_schedule

# Cifração AES: Passa o bloco de dados de 128 bits por 10 rodadas de cifração.
def cifracao_cifra_bloco_aes(plaintext, key):
  state = list(plaintext)
  key_schedule = key_expansion(key)
  state = add_round_key(state, key_schedule, 0)
  for round in range(1, 10):
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, key_schedule, round)
  state = sub_bytes(state)
  state = shift_rows(state)
  state = add_round_key(state, key_schedule, 10)
  return state

# Decifração AES: Passa o bloco cifrado de 128 bits por 10 rodadas de decifração.
def decifracao_cifra_bloco_aes(ciphertext, key):
  state = list(ciphertext)
  key_schedule = key_expansion(key)
  state = add_round_key(state, key_schedule, 10)
  for round in range(9, 0, -1):
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, key_schedule, round)
    state = inv_mix_columns(state)
  state = inv_shift_rows(state)
  state = inv_sub_bytes(state)
  state = add_round_key(state, key_schedule, 0)
  return state

# Operação XOR Bytes: Gerar o fluxo de chave que será combinado com os blocos de texto claro através de XOR para cifrar e decifrar os dados.
def xor_bytes(a, b):
  return [x ^ y for x, y in zip(a, b)]

# Conversão de inteiros para bytes.
def int_to_bytes(n, length):
  return n.to_bytes(length, 'big')

# Conversão de bytes para inteiros.
def bytes_to_int(b):
  return int.from_bytes(b, 'big')

# Cifração Modo de Operação CTR: Transformar uma cifra de bloco em uma cifra de fluxo e incrementa o contador para cada bloco cifrado.
def cifracao_modo_operacao_CTR(plaintext, key, nonce, counter):
  block_size = 16
  ciphertext = []
  for i in range(0, len(plaintext), block_size):
    block = plaintext[i:i + block_size]
    counter_block = nonce + int_to_bytes(counter, 8)
    encrypted_counter = cifracao_cifra_bloco_aes(counter_block, key)
    cipher_block = xor_bytes(block, encrypted_counter[:len(block)])
    ciphertext.extend(cipher_block)
    counter += 1
  return bytes(ciphertext)

# Decifração Modo CTR
def decifracao_modo_operacao_CTR(ciphertext, key, nonce, counter):
  return cifracao_modo_operacao_CTR(ciphertext, key, nonce, counter)

# Definindo um nonce de 64 bits (número único)
nonce = b'\x00' * 8

# Valor inicial do contador: AES deve ser utilizado para cifrar o valor do contador, que depois será combinado com o bloco de texto cifrado.
counter = 0

# Tamanho do Bloco de Dados: 128 bits ou 16 bytes.
plaintext = b'segurancaComputacional'

# Tamanho da Chave Secreta: 128 bits ou 16 bytes.
key = b'1234567890abcdef'

# Entrada recebe o bloco de dados de 128 bits para criptografar e uma chave secreta
ciphertext = cifracao_modo_operacao_CTR(plaintext, key, nonce, counter)

# Recebe o bloco criptografado de 128 bits para descriptografar e uma chave secreta
deciphertext = decifracao_modo_operacao_CTR(ciphertext, key, nonce, counter)

# Entrada sem estar criptografado em hexadecimal
print("Plain Text (Hexadecimal): ", bytes(plaintext).hex())

# Entrada sem estar criptografado em string
print("Plain Text (String): ", bytes(plaintext).decode())

# Saída que resulta no bloco de dados de 128 bits criptografado em hexadecimal.
print("Cipher Text (Hexadecimal): ", bytes(ciphertext).hex())

# Saída que resulta no bloco de dados de 128 bits descriptografado em hexadecimal.
print("Decipher Text (Hexadecimal): ", bytes(deciphertext).hex())

# Saída que resulta no bloco de dados de 128 bits descriptografado em hexadecimal.
print("Decipher Text (String): ", bytes(deciphertext).decode())

# Abre o arquivo teste.txt e pega o conteúdo em bytes
with open('teste.txt', 'rb') as file:
  plaintext = file.read()
  ciphertext = cifracao_modo_operacao_CTR(plaintext, key, nonce, counter)
  file.close()

# Cria um arquivo teste_encriptado.bin que contém o conteúdo de teste.txt encriptado
with open('teste_encriptado.txt', 'wb') as file:
  file.write(ciphertext)
  file.close()

# Abre o arquivo teste_encriptado.bin e pega o conteúdo em bytes
with open('teste_encriptado.txt', 'rb') as file:
  cyphertext = file.read()
  deciphertext = decifracao_modo_operacao_CTR(cyphertext, key, nonce, counter)
  file.close()
  
# Cria um arquivo teste_desencriptado.txt que contém o conteúdo de teste_encriptado.bin desencriptado
with open('teste_desencriptado.txt', 'wb') as file:
  file.write(deciphertext)
  file.close()

# Cria um arquivo teste_desencriptado.txt que contém o conteúdo de teste_encriptado.bin desencriptado
with open('teste_desencriptado.txt', 'wb') as file:
  file.write(deciphertext)
