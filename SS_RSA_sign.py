
import math
import hashlib
import random

def chameleon_hash(msg, r):
    msg_bytes = msg.encode('utf-8')

    msg_hash = hashlib.sha256(msg_bytes).digest()
    r_hash = hashlib.sha256(str(r).encode('utf-8')).digest()

    combined = bytes([a ^ b for a, b in zip(msg_hash, r_hash)])
    hash_result = hashlib.sha256(combined).hexdigest()

    return hash_result
#l is a defined length and K is the seed. These are defined apriori
l=32
K = 123  # Seed

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True

    if n % 2 == 0 or n % 3 == 0:
        return False

    # Check divisibility by numbers of the form 6k ± 1 up to √n
    for i in range(5, math.isqrt(n) + 1, 6):
        if n % i == 0 or n % (i + 2) == 0:
            return False

    return True

def generate_primes(l):
    """Generate two prime numbers with l/2 + 1 bits."""
    while True:
        p = random.getrandbits(l // 2 + 1)
        if p % 2 == 0:
            p += 1
        if is_prime(p):
            break

    while True:
        q = random.getrandbits(l // 2 + 1)
        if q % 2 == 0:
            q += 1
        if is_prime(q) and q != p:
            break

    return p, q


def generate_elements(p, q):
    """Generate random elements in ZN."""
    N = p * q
    h = random.randint(2, N - 1)
    c = random.randint(2, N - 1)
    c_binary = bin(c)[2:]

    return h, c_binary


def generate_keys(l, K):
    """Generate prime numbers and random elements."""
    p, q = generate_primes(l)
    h, c = generate_elements(p, q)

    return [[p, q, h, c, K], [p * q, h, c, K]]


#turns a string into binary using utf8
def encode_to_bits(string):
    # Encode string to UTF-8 bytes
    utf8_bytes = string.encode('utf-8')

    # Convert each byte to its binary representation
    binary_list = [format(byte, '08b') for byte in utf8_bytes]

    # Concatenate the binary representations
    binary_string = ''.join(binary_list)

    # Convert the binary string to an integer
    binary_number = int(binary_string, 2)

    return bin(binary_number)[2:]


def decode_from_bits(binary_number):
    # Convert the binary number to a binary string
    binary_string = binary_number  # Remove the '0b' prefix

    # Pad the binary string with leading zeros if necessary
    num_bits = len(binary_string)
    if num_bits % 8 != 0:
        binary_string = '0' * (8 - (num_bits % 8)) + binary_string

    # Split the binary string into 8-bit chunks
    binary_list = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]

    # Convert each 8-bit binary to decimal
    decimal_list = [int(binary, 2) for binary in binary_list]

    # Convert the decimal values to bytes
    utf8_bytes = bytes(decimal_list)

    # Decode bytes using UTF-8
    decoded_string = utf8_bytes.decode('utf-8')

    return decoded_string




def xor_strings(str1, str2):
    # Determine the lengths of the input strings
    len1 = len(str1)
    len2 = len(str2)

    # Make the lengths equal by adding zeros to the left of the smaller string
    if len1 < len2:
        str1 = str1.zfill(len2)
    elif len1 > len2:
        str2 = str2.zfill(len1)

    # Perform the XOR operation
    result = ''.join(str(int(a) ^ int(b)) for a, b in zip(str1, str2))

    return result

def pseudorandom_function(K, i, z, l):
    prng = random.Random(K)  # Create a deterministic pseudorandom number generator

    # Convert the integer and binary string inputs to a single string
    input_string = str(K) + str(i) + z

    # Set the seed for the deterministic pseudorandom number generator
    prng.seed(input_string)

    # Generate a random binary string of length l
    random_string = ''.join(prng.choice(['0', '1']) for _ in range(l))

    return random_string


def H(K, c, z):
    i = 1
    while True:
        prf_result = pseudorandom_function(K, bin(i)[2:], z, l)
        result = xor_strings(prf_result, c)
        res=int(result,2)

        if res % 2 == 1 and is_prime(res):
            return bin(res)[2:]
        i += 1

#takes the message (any string) and the private key and returns the binary signature
def sign_message(message, private_key):
    # Unpack the private key
    p, q,h,c,K= private_key

    tot=(p-1)*(q-1)
    N=p*q

    # Convert the message to a bit string
    M = encode_to_bits(message)

    #compute exponent
    exponent=1
    for i in range(1, len(M)+1):
        e=H(K, c, str(M[:i]))
        exponent *= pow(int(e,2), -1, tot)
        exponent=exponent % tot
    # Sign the message using RSA
    signature = pow(h, exponent, N)

    return bin(signature)[2:]


def verify_signature(message, signature, public_key):
    # Unpack the public key
    N,h, c, K = public_key

    # Convert the signature to an integer

    signature_int = int(signature,2)

    # Convert the message to a bit string
    M = encode_to_bits(message)

    #compute exponent
    exponent=1
    decoded_signature=signature_int

    for i in range(1, len(M)+1):
        e=H(K, c, M[:i])
        decoded_signature= pow(decoded_signature, int(e,2), N)



    m = decoded_signature

    # Convert the message to an integer
    expected_m = int(h)

    # Compare the computed message with the expected message
    return m == expected_m



#print( sign_message("ola", private_key))

keys=generate_keys(l,K)
private_key=keys[0]
public_key=keys[1]



print(verify_signature(chameleon_hash("love", 98), sign_message(chameleon_hash("love", 98), private_key), public_key))

print(verify_signature("love", sign_message("hate", private_key), public_key))



print(chameleon_hash("love", 98))
