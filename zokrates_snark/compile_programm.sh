#!/bin/bash
zokrates compile -i merkle_proof_pedersen.zok
# perform the setup phase
zokrates setup
# Export verifier
zokrates export-verifier --output ../contracts/verifier.sol

# Remove everything that's not needed
rm abi.json out.r1cs