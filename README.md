# zk-vote-hackathon
Playing around with Zero-Knowledge proofs for anonymous voting

## Setup

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

## Running the server

Make sure all public keys of people with a vote right are included in `PUBLIC_KEY_WHITELIST` in `src/voting_server.py`.

To run flask app:

```
$ cd src
$ FLASK_APP=voting_server flask run -h 0.0.0.0
```

Then, navigate to [http://localhost:5000/status](http://localhost:5000/status) to see the current state of the server.

## Voting

If you don't have a signing key yet, generate one by running:
```
$ openssl genrsa -out private_key.pem 1024
```

This will generate a `private_key.pem` in your working directory, which should be kept secret.
Note that the public key first needs to be whitelisted, as mentioned above.

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
