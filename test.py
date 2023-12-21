# sha3_256.py
import numpy as np
import hashlib

class SHA3_256_Sponge:
    def __init__(self):
        self.state = np.zeros((5, 5, 64), dtype=bool)  # Utilisation d'un tableau NumPy pour l'état
        self.rate = 1088  # 1088 bits pour SHA3-256
        self.capacity = 512  # 512 bits pour SHA3-256
        self.block_size = self.rate // 8  # Taille du bloc en octets
        self.output_length = 256  # Longueur de sortie pour SHA3-256

    def keccak_f(self):
        for round in range(24):
            self.theta()
            self.rho()
            self.pi()
            self.chi()
            self.iota(round)

    def theta(self):
        C = np.zeros((5, 64), dtype=bool)
        for x in range(5):
            C[x] = self.state[x, 0] ^ self.state[x, 1] ^ self.state[x, 2] ^ self.state[x, 3] ^ self.state[x, 4]
        D = np.zeros((5, 64), dtype=bool)
        for x in range(5):
            D[x] = C[(x - 1) % 5] ^ np.roll(C[(x + 1) % 5], -1)
        for x in range(5):
            for y in range(5):
                self.state[x, y] ^= D[x]

    def rho(self):
        rotations = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14]
        ]
        for x in range(5):
            for y in range(5):
                self.state[x, y] = np.roll(self.state[x, y], rotations[x][y])

    def pi(self):
        new_state = np.zeros((5, 5, 64), dtype=bool)
        for x in range(5):
            for y in range(5):
                new_state[y, (2 * x + 3 * y) % 5] = self.state[x, y]
        self.state = new_state

    def chi(self):
        new_state = np.zeros((5, 5, 64), dtype=bool)
        for x in range(5):
            for y in range(5):
                new_state[x, y] = self.state[x, y] ^ ((~self.state[(x + 1) % 5, y]) & self.state[(x + 2) % 5, y])
        self.state = new_state

    def iota(self, round):
        RC = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
            0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
            0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
            0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
            0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
            0x8000000000008080, 0x0000000080000001, 0x8000000080008008
        ]
        rc = np.array(list(bin(RC[round])[2:].rjust(64, '0')), dtype=bool)
        self.state[0, 0] ^= rc

    def pad(self, input_bytes):
        # Calcul de la longueur de padding nécessaire
        input_length = len(input_bytes) * 8  # Longueur en bits
        padding_length = self.rate - (input_length % self.rate)
        if padding_length == 0:
            padding_length = self.rate

        # Le padding se compose d'un '1', suivi de zéros nécessaires et se termine par un '1'
        padding_bits = [1] + [0] * (padding_length - 2) + [1]

        # Convertir le padding en bytes
        padding_bytes = self.bits_to_bytes(padding_bits)

        # Ajouter le padding au message
        return input_bytes + padding_bytes

    @staticmethod
    def bytes_to_bits(data):
        # Conversion des octets en bits
        result = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        return result.astype(bool)

    @staticmethod
    def bits_to_bytes(bits):
        # Conversion des bits en octets
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte |= bits[i + j] << j
            result.append(byte)
        return result

    def absorb(self, input_data):
        # Méthode pour absorber les données dans la structure Sponge
        input_data = self.pad(input_data)  # Appliquer le padding au message d'entrée
        for i in range(0, len(input_data), self.block_size):
            block = input_data[i:i + self.block_size]
            self.absorb_block(block)

    def absorb_block(self, block):
        # Absorption d'un bloc de données dans l'état
        block_bits = self.bytes_to_bits(block)
        block_bits_np = np.array(block_bits, dtype=bool)  # Convertir en tableau NumPy de type booléen

        # Créer un tableau temporaire de la taille de l'état avec des zéros
        temp_state = np.zeros_like(self.state)

        # Remplir uniquement la partie 'rate' du tableau temporaire avec block_bits_np
        temp_state.ravel()[:self.rate] = block_bits_np

        # Appliquer XOR sur l'état
        self.state ^= temp_state

        self.keccak_f()


    def squeeze(self):
        # Extraire le hachage de la structure Sponge
        z = bytearray()
        while len(z) < self.output_length // 8:
            squeezed_bits = np.packbits(self.state.reshape(-1)[:self.rate])
            squeezed_bytes = squeezed_bits.tobytes()
            z += squeezed_bytes[:(self.output_length // 8) - len(z)]
            self.keccak_f()  # Après chaque squeeze, appliquer keccak_f
        return z[:self.output_length // 8]

    def hexdigest(self):
        # Obtenir le hachage final sous forme hexadécimale
        hash_bytes = self.squeeze()
        return hash_bytes.hex()

def sha3_256(data):
    hasher = SHA3_256_Sponge()
    hasher.absorb(data)
    return hasher.hexdigest()

# Test
data = "test"
custom_hash_value = sha3_256(data.encode())
print("Custom SHA3-256:", custom_hash_value)

hash_sha3_256 = hashlib.sha3_256(data.encode()).hexdigest()
print("hashlib SHA3-256:", hash_sha3_256)

print("Correspondance:", custom_hash_value == hash_sha3_256)

