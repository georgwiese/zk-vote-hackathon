from abc import ABC, abstractmethod
from Crypto.Hash import SHA256
import hashlib
import sys
import shutil
import os
import random
from pathlib import Path
import json
from typing import List, Tuple
from tempfile import TemporaryDirectory
from zokrates_pycrypto.gadgets.pedersenHasher import PedersenHasher

class AbstractProver(ABC):

    @abstractmethod
    def compute_commit(self, serial_number: bytes, secret: bytes, vote: bool) -> bytes:
        pass

    @abstractmethod
    def compute_proof(self, serial_number: bytes, secret: bytes, vote: bool, known_hashes: List[bytes]) -> Tuple[dict, List[bytes]]:
        pass
    
    @abstractmethod
    def verify(self, serial_number: bytes, vote: bool, known_hashes: List[bytes], proof: dict) -> None:
        pass

class ZokratesProver(AbstractProver):

    def __init__(self, project_dir: Path):
        
        self.project_dir = project_dir

    def bytes_to_u32_list(self, input_bytes: bytes) -> List[int]:
        """Converts bytes to a list of 32-bit integers."""

        assert len(input_bytes) % 4 == 0
        length = len(input_bytes) // 4

        return [
            int.from_bytes(input_bytes[i : i + 4], "big")
            for i in range(0, len(input_bytes), 4)
        ]

    def bytes_to_u32_string(self, input_bytes: bytes) -> str:

        return " ".join([str(i) for i in self.bytes_to_u32_list(input_bytes)])

   
    def compute_commit(self, serial_number: bytes, secret: bytes, vote: bool) -> bytes:

        assert len(serial_number) == 128 // 8
        assert len(secret) == 128 // 8

        vote_bytes = int(vote).to_bytes(32, "big")
        bytes_to_hash = serial_number + secret + vote_bytes

        hasher = hashlib.sha256()
        hasher.update(bytes_to_hash)
        return hasher.digest()


    def compute_proof(self, serial_number: bytes, secret: bytes, vote: bool, known_hashes: List[bytes]) -> Tuple[dict, List[bytes]]:

        # Make sure that we have the right number of known hashes
        N = 10
        if len(known_hashes) <= N:
            # Fill up with zeros
            known_hashes += [(0).to_bytes(32, "big")] * (N - len(known_hashes))
        else:
            # Sample N hashes, making sure the correct one is included
            correct_hash = self.compute_commit(serial_number, secret, vote)
            known_hashes = random.sample(known_hashes, N)
            if not correct_hash in known_hashes:
                # Replace random hash with correct hash
                known_hashes[random.randrange(N)] = correct_hash

        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            serial_number_str = self.bytes_to_u32_string(serial_number)
            secret_str = self.bytes_to_u32_string(secret)
            known_hashes_str = " ".join([
                self.bytes_to_u32_string(known_hash)
                for known_hash in known_hashes
            ])

            compute_witness_command = f"zokrates compute-witness -a {int(vote)} {serial_number_str} {secret_str} {known_hashes_str}"

            shutil.copyfile(str(self.project_dir / "zokrates_snark" / "out"), tmpdir / "out")
            shutil.copyfile(str(self.project_dir / "zokrates_snark" / "proving.key"), tmpdir / "proving.key")
            shutil.copyfile(str(self.project_dir / "zokrates_snark" / "verification.key"), tmpdir / "verification.key")
            assert os.system(
                f"cd {tmpdir} && {compute_witness_command} && zokrates generate-proof && zokrates inspect && zokrates verify"
            ) == 0

            with (tmpdir / "proof.json").open("r") as f:
                return json.load(f), known_hashes
    

    def verify(self, serial_number: bytes, vote: bool, known_hashes: List[bytes], proof: dict) -> None:
        with TemporaryDirectory() as tmpdir:

            tmpdir = Path(tmpdir)

            shutil.copyfile(str(self.project_dir / "zokrates_snark" / "verification.key"), tmpdir / "verification.key")

            with (tmpdir / "proof.json").open("w") as f:
                json.dump(proof, f)

            assert os.system(
                f"cd {str(tmpdir)} && zokrates verify"
            ) == 0

            # Also assert that the public inputs to the proof are as expected
            assert len(proof["inputs"]) == 85
            actual_inputs_hex = "".join(
                [s[-8:] for s in proof["inputs"]]
            )
            expected_inputs_hex = (
                int(vote).to_bytes(4, "big").hex()
                + serial_number.hex()
                + "".join(known_hash.hex() for known_hash in known_hashes)
            )
            assert actual_inputs_hex == expected_inputs_hex, f"{actual_inputs_hex} does not match {expected_inputs_hex}!"


if __name__ == "__main__":

    # Simple test case
    strategy = ZokratesProver(Path("."))
    
    serial_number = os.urandom(128 // 8)
    secret = os.urandom(128 // 8)
    vote = True

    commit = strategy.compute_commit(serial_number, secret, vote)

    known_hashes = [commit] + [os.urandom(256 // 8) for _ in range(12)]
    proof, known_hashes = strategy.compute_proof(serial_number, secret, vote, known_hashes)

    strategy.verify(serial_number, vote, known_hashes, proof)