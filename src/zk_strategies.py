from abc import ABC, abstractmethod
from Crypto.Hash import SHA256
import hashlib
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher

class ZkStrategy(ABC):

    @abstractmethod
    def compute_commit(self, serial_number: bytes, secret: bytes, vote: bool) -> bytes:
        pass

class ZokratesZkStrategy(ZkStrategy):

    def compute_commit(self, serial_number: bytes, secret: bytes, vote: bool) -> bytes:
        """Compute the hash of:
           - Serial number (128 bit)
           - Secret (128 bit)
           - Padding (127 bit)
           - Vote (1 bit)
        """

        pad = (0).to_bytes(31, "big")
        vote_byte = (1).to_bytes(1, "big") if vote else (1).to_bytes(1, "big")
        bytes_to_hash = serial_number + secret + pad + vote_byte

        bytes_to_hash = (0).to_bytes(64, "big")

        print(len(serial_number), len(secret), len(pad), len(vote_byte), len(bytes_to_hash), bytes_to_hash.hex())

        # See: https://github.com/Zokrates/pycrypto/
        hasher = PedersenHasher(b"test")
        digest = hasher.hash_bytes(bytes_to_hash)
        print(digest)

        foo = hashlib.sha256()
        foo.update(bytes_to_hash)
        return foo.digest()

        return SHA256.new(bytes_to_hash).digest()
