import typer
import hashlib
import os
import requests
import json

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

VOTE_SERVER = "http://0.0.0.0:5000"

app = typer.Typer()

@app.command()
def vote(vote: bool):

    serial_number = os.urandom(128 // 8)
    secret = os.urandom(128 // 8)

    commitment = SHA256.new()
    commitment.update(serial_number)
    commitment.update(secret)
    commitment.update(b"Y" if vote else b"N")

    commitment_hash = SHA256.new()
    commitment_hash.update(commitment.hexdigest().encode("utf-8"))

    with open("private_key.pem", "r") as src:
        private_key = RSA.importKey(src.read())
    public_key_bytes = private_key.publickey().exportKey()
    public_key = public_key_bytes.decode("utf-8")

    signer = PKCS1_v1_5.new(private_key)
    signature = signer.sign(commitment_hash)

    print(f"Serial number: {serial_number}")
    print(f"Secret:        {secret}")
    print(f"Vote:          {vote}")
    print(f"Commitment:    {commitment.hexdigest()}")
    print(f"Public key:    {public_key_bytes}")
    print(f"Signature:     {signature.hex()}")

    vote_data = {
        "commitment": commitment.hexdigest(),
        "public_key": public_key,
        "signature": signature.hex(),
    }

    r = requests.post(f"{VOTE_SERVER}/vote", json=vote_data)

    assert r.status_code == 200, r.text

    with open("vote.json", "w") as f:
        json.dump({
            "serial_number": serial_number.hex(),
            "secret": secret.hex(),
            "vote": vote,
        }, f)
    print("Vote was saved to vote.json. Keep it secret!")

@app.command()
def reveal():

    with open("vote.json", "r") as f:
        vote_data = json.load(f)

    serial_number = vote_data["serial_number"]
    secret = vote_data["secret"]
    vote = vote_data["vote"]

    commitments = requests.get(f"{VOTE_SERVER}/status").json()["commitments"]

    # TODO: Generate proof

    reveal_data = {
        "serial_number": serial_number,
        "vote": vote,
        "commitments": commitments,
    }

    r = requests.post(f"{VOTE_SERVER}/reveal_vote", json=reveal_data)
    assert r.status_code == 200, r.text

if __name__ == "__main__":
    app()