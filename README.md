# zk-vote-hackathon
A quick-and-dirty hackathon project, building a simple voting protocol using zero-knowledge proofs.

The basic protocol is inspired by [Zerocoin](https://zerocoin.org/) and works as follows:
- To cast a vote, a voter with a white-listed public key does the following:
  - It generates a random 128-bit `secret`
  - It generates a random 128-bit `serial_number`
  - It choses a boolean `vote` (yes or no)
  - It computes a `commit = Hash(secret, serial_number, vote)`, and sends it to the voting server, signed with its public key
- The voting server collects and publishes all commits
- Then, the voter can reveal the vote, by publishing the `serial_number`, `vote`, and a zero-knowledge prove that it knows a `secret` such that it computes to a `commit` that is in the public list of all commits. The voting server:
  - Validates the proof
  - Ensures that the same serial number is not used more than once
  - Publishes the voting result
  
Because the connection between the `serial_number` and the `commit` never is revealed, the `vote` cannot be connected to the voter's public key.

## Setup

### Via Docker

```bash
$ docker build . -t zk-vote-container
```

```
$ docker run --rm --name vscode \
  -it -p 8443:8443 -p 5000:5000 \
  -v $(pwd):/code \
  zk-vote-container
```

Then, connect to [http://localhost:8443](http://localhost:8443) for a Visual Studio Code Session.
The password necessary to access VS Code will be printed in the console.

### Local setup

- Install Zokrates by running `curl -LSfs get.zokrat.es | sh` and adding `~/.zokrates/bin` to your `PATH` variable.
- (Linux: Run `apt install libgmp3-dev`)
- Run `pip install -r ./requirements.txt`
- Run `npm install`

## Running the server

Make sure all public keys of people with a vote right are included in the `accepted_public_keys` directory when the server starts.

To run flask app:

```
$ cd src && FLASK_APP=voting_server FLASK_ENV=development python -m flask run -h 0.0.0.0
```

Then, navigate to [http://localhost:5000/status](http://localhost:5000/status) to see the current state of the server.

## Voting (Server implementation)

If you don't have a signing key yet, generate one by running:
```
$ openssl genrsa -out private_key.pem 1024
```

This will generate a `private_key.pem` in your working directory, which should be kept secret.

Extract the public key by running:
```
openssl rsa -in private_key.pem -outform PEM -pubout -out key.pub
```
To whitelist the public key, copy `key.pub` into `accepted_public_keys`.

Before the first run, compile the proof:
```
cd zokrates_snark/ && ./compile_programm.sh
```

To vote, run:
```
$ python src/vote_cli.py vote <vote>
```

where `<vote>` can be `yes` or `no`.
This will generate a `vote.json` in your working directory, which should be kept secret.

To reveal the vote, run:
```
$ python src/vote_cli.py reveal
```

Finally, navigate to [http://localhost:5000/status](http://localhost:5000/status) to see the voting result.

## Voting (Ethereum implementation)

To test the solidity contracts locally install [hardhat](https://hardhat.org/hardhat-runner/docs/getting-started) and
run your local node

Compile the contracts
```
npx hardhat compile
```

### Connect to local Hardhat node

Run `npx hardhat node` to start the local ethereum node.
Then, make sure that `USE_HARDHAT = True` in `vote_cli.py`.

### Connect to Görli test net

Set the `GOERLI_ENDPOINT_URL` and `ETH_PRIVATE_KEY` environment variables, and make sure that `USE_HARDHAT = False` in `vote_cli.py`.

### Setup

To deploy the smart contract, run:

```bash
python src/vote_cli.py eth-deploy-voting-contract
```

Or, to participate in an already deployed vote, run:

```bash
python src/vote_cli.py eth-set-deployed-contract <address>
```

Next, ask the chairperson (the account who deployed the contract) to give you a voting right by running:

```bash
python src/vote_cli.py eth-give-right-to-vote <your address>
```

### Vote

The voting consists of two steps: First, you commit to a vote by running:

```bash
python src/vote_cli.py eth-vote <yes/no>
```

This needs to be run using the account that has voting rights.
As a result, this transaction can be connected to your identity.
However, this will send your vote in encrypted form, so privacy is preserved.

### Start the reveal phase

Next, the chairperson has to set the Merkle root to be used for all the reveal proofs:

```bash
python src/vote_cli.py eth-set-merkle-root
```

In the next step, the Merkle root is re-computed by all the voters.
If the chairperson sets an incorrect Merkle root, all the reveals fail.
So, one has to trust the chairperson not to freeze the election.

### Reveal your vote

Next, reveal your vote by running:

```bash
python src/vote_cli.py eth-reveal
```

This will decrypt your vote.
This can be run using any account, so use one that cannot be connected to your identity to preserve privacy.

### Result

As a last step, get the result by running:

```bash
python src/vote_cli.py eth-get-results
```