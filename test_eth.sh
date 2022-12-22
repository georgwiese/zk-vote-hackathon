set -e

npx hardhat compile
python src/vote_cli.py deploy-voting-contract
python src/vote_cli.py vote-eth yes
python src/vote_cli.py reveal-eth