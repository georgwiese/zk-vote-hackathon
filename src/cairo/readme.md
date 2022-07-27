# install giza
cd ..
git clone git@github.com:maxgillett/giza.git
cd giza
cargo install --path cli
cd ../zk-vote-hackathon/src/cairo

# compile cairo program and create trace 
cairo-compile proof-legit-vote.cairo --output proof-legit-vote.json
cairo-run \
  --program=proof-legit-vote.json --print_output \
  --print_info --relocate_prints --layout small --program_input=voting_input.json --memory_file=memory.bin --trace_file=trace.bin

# prove and verify with giza
giza prove --trace=trace.bin --memory=memory.bin --program=proof-legit-vote.json --output=proof.bin --num-outputs 7
giza verify --proof=proof.bin