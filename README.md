# zk-vote-hackathon
Playing around with Zero-Knowledge proofs for anonymous voting

## Setup

```bash
$ docker build . -t zk-vote-container
```

```
$ docker run --rm --name vscode \
  -it -p 8443:8443 -p 8888:8888 \
  -v $(pwd):/code \
zk-vote-container
```