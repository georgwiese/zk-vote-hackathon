from flask import Flask, request
import json
import os

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

from provers import ZokratesProver

from pathlib import Path

PUBLIC_KEY_WHITELIST = []
for public_key_path in Path("../accepted_public_keys").glob("*.pub"):
    with public_key_path.open() as f:
        PUBLIC_KEY_WHITELIST.append(f.read().strip())

# Flask server is started from <project dir> / src
PROVER = ZokratesProver(Path(".."))

app = Flask(__name__)

keys_with_commitments = []
commitments = []
seen_serial_numbers = []
yes_votes = 0


@app.route("/vote", methods=["POST"])
def vote():
    data = json.loads(request.data)
    commitment = bytes.fromhex(data["commitment"])
    public_key_str = data["public_key"]
    signature = bytes.fromhex(data["signature"])

    assert public_key_str in PUBLIC_KEY_WHITELIST, (
        "Public key not in whitelist!\n"
        + f"Public key: {public_key_str}\n"
        + f"White list: {PUBLIC_KEY_WHITELIST}"
    )

    if "DEBUG_ALLOW_DOUBLE_VOTING" not in os.environ:
        assert public_key_str not in keys_with_commitments, "Public key already voted!"

    public_key = RSA.importKey(public_key_str)
    commitment_hash = SHA256.new()
    commitment_hash.update(commitment)
    verifier = PKCS1_v1_5.new(public_key)
    assert verifier.verify(commitment_hash, signature), "Signature does not verify!"

    commitments.append(commitment.hex())
    keys_with_commitments.append(public_key_str)

    return "OK"


@app.route("/reveal_vote", methods=["POST"])
def reveal_vote():

    global yes_votes

    data = json.loads(request.data)
    serial_number = bytes.fromhex(data["serial_number"])
    vote = data["vote"]
    commitments_for_proof = data["commitments"]
    proof = data["proof"]

    assert serial_number not in seen_serial_numbers, "Serial number already revealed!"
    for commitment in commitments_for_proof:
        if commitment != "0" * 64:  # Prover is allowed to add zero hashes
            assert commitment in commitments, f"Proof used unknown commitments: {commitment}"

    PROVER.verify(serial_number, vote, [bytes.fromhex(c_hex) for c_hex in commitments_for_proof], proof)

    seen_serial_numbers.append(serial_number)
    if vote:
        yes_votes += 1

    return "OK"

@app.route("/status")
def status():
    return {
        "yes_votes": yes_votes,
        "total_commitments": len(commitments),
        "total_revealed_votes": len(seen_serial_numbers),
        "commitments": commitments,
    }
