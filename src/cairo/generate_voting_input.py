from starkware.crypto.signature.signature import pedersen_hash
import json

secrets = [1, 2, 3, 4, 5]
serial_nrs = [1, 2, 3, 4, 5]
votes = [0, 1, 1, 0, 1]

cms = []

for vote, serial_nr, secret in zip(votes, serial_nrs, secrets):
	cms.append(pedersen_hash(vote, pedersen_hash(serial_nr, secret)))

input_dict = {
	"commits": cms,
	"vote": votes[0],
	"serial_nr": serial_nrs[0],
	"secret": secrets[0]
}


with open('voting_input.json', 'w') as f:
	json.dump(input_dict, f, indent=4)
	f.write('\n')