from flask import Flask, request
import json

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA

from pathlib import Path

PUBLIC_KEY_WHITELIST = []
for public_key_path in Path("../accepted_public_keys").glob("*.pub"):
    with public_key_path.open() as f:
        PUBLIC_KEY_WHITELIST.append(f.read())

app = Flask(__name__)

keys_with_commitments = []
commitments = []
seen_serial_numbers = []
yes_votes = 0


@app.route("/vote", methods=["POST"])
def vote():
    data = json.loads(request.data)
    commitment = data["commitment"]
    public_key_str = data["public_key"]
    signature = bytes.fromhex(data["signature"])
    
    assert (
        public_key_str in PUBLIC_KEY_WHITELIST,
        "Public key not in whitelist!\n"
        + f"Public key: {public_key_str}\n"
        + f"White list: {PUBLIC_KEY_WHITELIST}"
    )
    assert public_key_str not in keys_with_commitments, "Public key already voted!"

    public_key = RSA.importKey(public_key_str)
    commitment_hash = SHA256.new()
    commitment_hash.update(commitment.encode("utf-8"))
    verifier = PKCS1_v1_5.new(public_key)
    assert verifier.verify(commitment_hash, signature), "Signature does not verify!"

    commitments.append(commitment)
    keys_with_commitments.append(public_key_str)

    return "OK"



@app.route("/reveal_vote", methods=["POST"])
def reveal_vote():

    global yes_votes

    data = json.loads(request.data)
    serial_number = data["serial_number"]
    vote = data["vote"]
    commitments_for_proof = data["commitments"]

    assert serial_number not in seen_serial_numbers, "Serial number already revealed!"
    for commitment in commitments_for_proof:
        assert commitment in commitments, "Proof used unknown commitments!"

    # TODO: Verify proof

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