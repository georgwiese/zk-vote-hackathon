set -e

npx hardhat compile
python src/vote_cli.py eth-deploy-voting-contract
# Right to vote for second hardhat account
#python src/vote_cli.py eth-give-right-to-vote 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
python src/vote_cli.py eth-vote yes
python src/vote_cli.py eth-set-merkle-root
python src/vote_cli.py eth-reveal
python src/vote_cli.py eth-get-results