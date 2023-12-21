# sha3_256.py
import numpy as np
import hashlib

class SHA3_256:
    def __init__(self):
        self.state = np.zeros((5, 5, 64), dtype=bool)
        self.rate = 1088
        self.capacity = 512
        self.output_length = 256
        self.block_size = self.rate // 8
        self.buffer = bytearray()

    def pad(self, data):
        P = data + b'\x01'  # Ajoute le premier bit '1'
        L = len(P) % self.block_size
        if L > 0:
            P += b'\x00' * (self.block_size - L - 1)  # Ajoute les bits '0'
        P += b'\x80'  # Ajoute le dernier bit '1'
        return P


    def update(self, data):
        print(data)
        self.buffer += data
        while len(self.buffer) >= self.block_size:
            block = self.buffer[:self.block_size]
            self.buffer = self.buffer[self.block_size:]
            self.absorb_block(block)

    def absorb_block(self, block):
        block_bits = np.unpackbits(np.frombuffer(block, dtype=np.uint8))
        block_bits = block_bits.reshape((-1, 64)).astype(bool)
        for i in range(block_bits.shape[0]):
            self.state[i // 5, i % 5] ^= block_bits[i]
        self.keccak_f()

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

    def squeeze(self):
        Z = bytearray()
        while len(Z) < self.output_length // 8:
            squeezed_bits = np.packbits(self.state.reshape(-1)[:self.rate])
            squeezed_bytes = squeezed_bits.tobytes()
            Z += squeezed_bytes[:(self.output_length // 8) - len(Z)]
            self.keccak_f()
        return Z


    def digest(self):
        self.update(self.pad(self.buffer))  # Applique le padding aux données accumulées
        self.buffer = bytearray()  # Réinitialise le buffer après le padding
        return self.squeeze()


    def hexdigest(self):
        return self.digest().hex()

def sha3_256(data):
    hasher = SHA3_256()
    hasher.update(data)
    return hasher.hexdigest()

data = "test"
hash_value = sha3_256(data.encode())
print(hash_value)
hash_sha3_256 = hashlib.sha3_256(data.encode()).hexdigest()
print(hash_sha3_256)
print(hash_value == hash_sha3_256)
