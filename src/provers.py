from abc import ABC, abstractmethod
import hashlib
import shutil
import os
from pathlib import Path
import json
import math
from typing import List, Tuple
from tempfile import TemporaryDirectory

# If this constant is adjusted, the one in merkle_proof.zok also needs to be adjusted
MERKLE_TREE_DEPTH = 3

def hash_bytes(bytes_to_hash: bytes):
    hasher = hashlib.sha256()
    hasher.update(bytes_to_hash)
    return hasher.digest()

def calculate_merkle_tree(
    hashes: List[bytes],
    expected_length: int,
    current_hash: bytes = None,
    directions: List[bool] = [],
    path: List[bytes] = []
):
    assert math.log2(expected_length).is_integer(), f"Merkle tree expected length needs to be a power of 2, but is {expected_length}"
    # If there are not enough elements, fill up with zeros
    hashes += [(0).to_bytes(32, "big")] * (expected_length - len(hashes))

    if len(hashes) == 1:
        return hashes[0], directions, path

    new_hashes = []
    for i in range(0, len(hashes) - 1, 2):
        new_hashes.append(hash_bytes(hashes[i] + hashes[i + 1]))

        # Memorize the path and directions
        if hashes[i] == current_hash:
            directions.append(False)
            path.append(hashes[i + 1])
            current_hash = new_hashes[-1]
        elif hashes[i + 1] == current_hash:
            directions.append(True)
            path.append(hashes[i])
            current_hash = new_hashes[-1]

    return calculate_merkle_tree(new_hashes, expected_length // 2, current_hash, directions, path)

class AbstractProver(ABC):

    @abstractmethod
    def compute_commit(self, serial_number: bytes, secret: bytes, vote: bool) -> bytes:
        """Hashes serial number, secret, and vote."""
        pass

    @abstractmethod
    def compute_proof(self, serial_number: bytes, secret: bytes, vote: bool, known_hashes: List[bytes]) -> Tuple[dict, bytes]:
        """Computes a proof that serial number, secret, and vote hash to a value that's in `known_hashes`.
        
        The `known_hashes` might be modified by the prover, for example by sampling a subset,
        or adding zero hashes. The modified `known_hashes` are returned with the proof.
        """
        pass
    
    @abstractmethod
    def verify(self, serial_number: bytes, vote: bool, root: bytes, proof: dict) -> None:
        """Verfies a proof, including that fact that public arguments are as stated."""
        pass

class ZokratesProver(AbstractProver):

    def __init__(self, project_dir: Path):
        
        self.project_dir = project_dir

    def bytes_to_u32_list(self, input_bytes: bytes) -> List[int]:
        """Converts bytes to a list of 32-bit integers."""

        assert len(input_bytes) % 4 == 0

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


    def compute_proof(self, serial_number: bytes, secret: bytes, vote: bool, known_hashes: List[bytes]) -> Tuple[dict, bytes]:

        # Build merkle tree and compute merkle path
        correct_hash = self.compute_commit(serial_number, secret, vote)

        # Make sure that we have the right number of known hashes
        N = 2 ** MERKLE_TREE_DEPTH
        assert len(known_hashes) <= N, f"There are more than {N} votes which is not supported. Increase the DEPTH of the merkle tree."

        root, directions, path = calculate_merkle_tree(known_hashes, N, correct_hash)

        with TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            serial_number_str = self.bytes_to_u32_string(serial_number)
            secret_str = self.bytes_to_u32_string(secret)
            root_str = self.bytes_to_u32_string(root)
            directions_str = " ".join(list(map(str, [
                int(direction)
                for direction in directions
            ])))
            path_str = " ".join([
                self.bytes_to_u32_string(node)
                for node in path
            ])

            compute_witness_command = ("zokrates compute-witness -a " +
                f"{int(vote)} {serial_number_str} {secret_str} {root_str} {directions_str} {path_str}")

            shutil.copyfile(str(self.project_dir / "zokrates_snark" / "out"), tmpdir / "out")
            shutil.copyfile(str(self.project_dir / "zokrates_snark" / "proving.key"), tmpdir / "proving.key")
            shutil.copyfile(str(self.project_dir / "zokrates_snark" / "verification.key"), tmpdir / "verification.key")
            assert os.system(
                f"cd {tmpdir} && {compute_witness_command} && zokrates generate-proof && zokrates inspect && zokrates verify"
            ) == 0

            with (tmpdir / "proof.json").open("r") as f:
                return json.load(f), root
    

    def verify(self, serial_number: bytes, vote: bool, root: bytes, proof: dict) -> None:
        with TemporaryDirectory() as tmpdir:

            tmpdir = Path(tmpdir)

            shutil.copyfile(str(self.project_dir / "zokrates_snark" / "verification.key"), tmpdir / "verification.key")

            with (tmpdir / "proof.json").open("w") as f:
                json.dump(proof, f)

            assert os.system(
                f"cd {str(tmpdir)} && zokrates verify"
            ) == 0

            assert len(proof["inputs"]) == 13, f"Proof actually has {len(proof['inputs'])} inputs"
            actual_inputs_hex = "".join(
                [s[-8:] for s in proof["inputs"]]
            )
            expected_inputs_hex = (
                int(vote).to_bytes(4, "big").hex()
                + serial_number.hex()
                + root.hex()
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
    proof, root = strategy.compute_proof(serial_number, secret, vote, known_hashes)

    strategy.verify(serial_number, vote, root, proof)
