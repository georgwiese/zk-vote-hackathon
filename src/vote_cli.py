import json
import os
from pathlib import Path

import requests
import typer
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from web3 import Web3

from provers import ZokratesProver

VOTE_SERVER = "http://0.0.0.0:5000"
PROVER = ZokratesProver(Path("."))

app = typer.Typer()

USE_HARDHAT = False

if USE_HARDHAT:
    HTTP_ENDPOINT_URL = "http://127.0.0.1:8545"
else:
    # Connect to Görli test net
    assert "GOERLI_ENDPOINT_URL" in os.environ, "Please provide a Görli http endpoint via the GOERLI_ENDPOINT_URL environment variable"
    HTTP_ENDPOINT_URL = os.environ["GOERLI_ENDPOINT_URL"]

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


@app.command()
def eth_deploy_voting_contract():
    w3 = Web3(Web3.HTTPProvider(HTTP_ENDPOINT_URL))

    verifier_address = deploy_contract("artifacts/contracts/verifier.sol/Verifier.json", w3)
    ballot_address = deploy_contract("artifacts/contracts/Ballot.sol/Ballot.json", w3, verifier_address)

    with open("contract.json", "w") as f:
        json.dump({
            "contractAddress": ballot_address
        }, f)

    print(f"Contract deployed to {ballot_address}. Created contract.json to store the address.")


@app.command()
def eth_set_deployed_contract(ballot_address: str):

    with open("contract.json", "w") as f:
        json.dump({
            "contractAddress": ballot_address
        }, f)

    print(f"Created contract.json to store the address.")

@app.command()
def eth_give_right_to_vote(address: str):
    w3 = Web3(Web3.HTTPProvider(HTTP_ENDPOINT_URL))
    voting_contract_address = get_deployed_contract_address()

    voting_contract = get_voting_contract(voting_contract_address, w3)
    send_transaction(w3, voting_contract.functions.giveRightToVote(address).build_transaction())

@app.command()
def eth_vote(vote: bool):

    voting_contract_address = get_deployed_contract_address()

    serial_number = os.urandom(128 // 8)
    secret = os.urandom(128 // 8)

    commitment = PROVER.compute_commit(serial_number, secret, vote)

    print(f"Serial number: {serial_number.hex()}")
    print(f"Secret:        {secret.hex()}")
    print(f"Vote:          {vote}")
    print(f"Commitment:    {commitment.hex()}")

    w3 = Web3(Web3.HTTPProvider(HTTP_ENDPOINT_URL))
    voting_contract = get_voting_contract(voting_contract_address, w3)
    print("Sending vote...")
    send_transaction(w3, voting_contract.functions.vote(commitment.hex()).build_transaction({
        # Gas estimation fails for some reason, so set limit manually
        "gas": 2000000
    }))

    with open("vote.json", "w") as f:
        json.dump({
            "commitment": commitment.hex(),
            "serial_number": serial_number.hex(),
            "secret": secret.hex(),
            "vote": vote,
        }, f, indent=2)
    print("Vote was saved to vote.json. Keep it secret!")

@app.command()
def eth_reveal():

    voting_contract_address = get_deployed_contract_address()

    with open("vote.json", "r") as f:
        vote_data = json.load(f)

    serial_number = bytes.fromhex(vote_data["serial_number"])
    secret = bytes.fromhex(vote_data["secret"])
    vote = vote_data["vote"]

    # fetch known hashes from contract
    w3 = Web3(Web3.HTTPProvider(HTTP_ENDPOINT_URL))
    voting_contract = get_voting_contract(voting_contract_address, w3)

    # There has to be a better way of fetching all existing commits...
    num_commits = voting_contract.functions.numCommits().call()
    known_hashes = []
    for i in range(num_commits):
        known_hashes.append(voting_contract.functions.commitList(i).call())

    proof, known_hashes = PROVER.compute_proof(serial_number, secret, vote, known_hashes)

    def to_ints(hex_str):
        return (int(hex_str[0], 16), int(hex_str[1], 16))

    proof_abc = (to_ints(proof["proof"]["a"]), (to_ints(proof["proof"]["b"][0]), to_ints(proof["proof"]["b"][1])), to_ints(proof["proof"]["c"]))
    tx = voting_contract.functions.revealVote(vote, serial_number, known_hashes, proof_abc).build_transaction()
    send_transaction(w3, tx)


@app.command()
def eth_get_results():
    w3 = Web3(Web3.HTTPProvider(HTTP_ENDPOINT_URL))
    voting_contract_address = get_deployed_contract_address()
    voting_contract = get_voting_contract(voting_contract_address, w3)
    
    num_commits = voting_contract.functions.numCommits().call()
    yes_count = voting_contract.functions.yesCount().call()
    vote_count = voting_contract.functions.voteCount().call()
    percentage = int((yes_count / vote_count) * 100) if vote_count > 0 else "--"

    print(f"=== RESULTS ===")
    print(f"Number of votes: {num_commits}")
    print(f"Number of revealed votes: {vote_count}")
    print(f"Yes counts: {yes_count} ({percentage}%)")


def load_contract_abi_and_bytecode(contract_path):
    with open(contract_path, "r") as f:
        compiled_contract_json = json.load(f)
    abi = compiled_contract_json["abi"]
    bytecode = compiled_contract_json["bytecode"]
    return abi, bytecode


def send_transaction(w3, transaction):

    if USE_HARDHAT:
        # Hardhat default private key
        private_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        # Second account, for testing:
        # private_key = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    else:
        assert "ETH_PRIVATE_KEY" in os.environ, "Please provide a private key via the ETH_PRIVATE_KEY env variable"
        private_key = os.environ["ETH_PRIVATE_KEY"]

    address = w3.eth.account.from_key(private_key).address

    # Sometimes goes is not enough to deploy the contract...
    transaction["gas"] = transaction["gas"] * 2
    
    transaction["nonce"] = w3.eth.getTransactionCount(address)
    signed = w3.eth.account.sign_transaction(transaction, private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
    return w3.eth.wait_for_transaction_receipt(tx_hash)

def deploy_contract(contract_path, w3, *args):
    abi, bytecode = load_contract_abi_and_bytecode(contract_path)
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    transaction = contract.constructor(*args).build_transaction()
    tx_receipt = send_transaction(w3, transaction)
    return tx_receipt.contractAddress

def get_voting_contract(voting_contract_address, w3):
    abi, _ = load_contract_abi_and_bytecode("artifacts/contracts/Ballot.sol/Ballot.json")
    voting_contract = w3.eth.contract(address=voting_contract_address, abi=abi)
    return voting_contract

def get_deployed_contract_address():

    assert os.path.exists("contract.json"), "contract.json does not exist, run deploy-voting-contract command first!"

    with open("contract.json") as f:
        return json.load(f)["contractAddress"]

if __name__ == "__main__":
    app()