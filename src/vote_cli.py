import typer
import hashlib
import os
import requests
import json

from pathlib import Path
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from provers import ZokratesProver

VOTE_SERVER = "http://0.0.0.0:5000"
PROVER = ZokratesProver(Path("."))

app = typer.Typer()

@app.command()
def vote(vote: bool):

    serial_number = os.urandom(128 // 8)
    secret = os.urandom(128 // 8)

    commitment = PROVER.compute_commit(serial_number, secret, vote)

    commitment_hash = SHA256.new()
    commitment_hash.update(commitment)

    with open("private_key.pem", "r") as src:
        private_key = RSA.importKey(src.read())
    public_key_bytes = private_key.publickey().exportKey()
    public_key = public_key_bytes.decode("utf-8")

    signer = PKCS1_v1_5.new(private_key)
    signature = signer.sign(commitment_hash)

    print(f"Serial number: {serial_number.hex()}")
    print(f"Secret:        {secret.hex()}")
    print(f"Vote:          {vote}")
    print(f"Commitment:    {commitment.hex()}")
    print(f"Public key:    {public_key_bytes}")
    print(f"Signature:     {signature.hex()}")

    vote_data = {
        "commitment": commitment.hex(),
        "public_key": public_key,
        "signature": signature.hex(),
    }

    r = requests.post(f"{VOTE_SERVER}/vote", json=vote_data)

    assert r.status_code == 200, r.text

    with open("vote.json", "w") as f:
        json.dump({
            "commitment": commitment.hex(),
            "serial_number": serial_number.hex(),
            "secret": secret.hex(),
            "vote": vote,
        }, f)
    print("Vote was saved to vote.json. Keep it secret!")

@app.command()
def reveal():

    with open("vote.json", "r") as f:
        vote_data = json.load(f)

    serial_number = bytes.fromhex(vote_data["serial_number"])
    secret = bytes.fromhex(vote_data["secret"])
    vote = vote_data["vote"]

    known_hashes = [
        bytes.fromhex(hash_hex)
        for hash_hex in requests.get(f"{VOTE_SERVER}/status").json()["commitments"]
    ]

    proof, known_hashes = PROVER.compute_proof(serial_number, secret, vote, known_hashes)

    reveal_data = {
        "serial_number": serial_number.hex(),
        "vote": vote,
        "commitments": [hash_bytes.hex() for hash_bytes in known_hashes],
        "proof": proof,
    }

    r = requests.post(f"{VOTE_SERVER}/reveal_vote", json=reveal_data)
    assert r.status_code == 200, r.text

if __name__ == "__main__":
    app()