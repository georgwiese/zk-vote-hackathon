// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

contract Ballot {
    struct Voter {
        bool hasRightToVote;
        bool voted; // if true, that person already voted
    }

    struct Proposal {
        // If you can limit the length to a certain number of bytes,
        // always use one of bytes1 to bytes32 because they are much cheaper
        bytes32 name; // short name (up to 32 bytes)
        uint256 voteCount; // number of accumulated votes
    }

    address public chairperson;
    mapping(address => Voter) public voters;
    mapping(bytes32 => bool) public commits;
    bytes32[] public commitList;
    uint256 public numCommits;
    mapping(bytes32 => bool) public seenSerialNumbers;
    uint256 public yesCount;
    uint256 public voteCount;
    address public verifierContractAddress;

    constructor(address _verifierContractAddress) {
        chairperson = msg.sender;
        verifierContractAddress = _verifierContractAddress;

        voters[chairperson] = Voter({hasRightToVote: true, voted: false});
    }

    function giveRightToVote(address voter) public {
        require(
            msg.sender == chairperson,
            "Only chairperson can give right to vote."
        );
        require(!voters[voter].voted, "The voter already voted.");
        require(voters[voter].hasRightToVote == false);
        voters[voter].hasRightToVote = true;
    }

    function vote(bytes32 commit) public {
        Voter storage sender = voters[msg.sender];
        require(sender.hasRightToVote, "Has no right to vote");
        require(!sender.voted, "Already voted.");
        sender.voted = true;
        numCommits += 1;
        commits[commit] = true;
        commitList.push(commit);
    }

    function revealVote(
        bool _vote,
        bytes32 serialNumber,
        bytes32[10] memory commitsForProof,
        Verifier.Proof memory proof
    ) public {
        // validate proof
        // call sokrates
        uint256[85] memory proof_inputs;
        uint256 j = 0;
        if (_vote) {
            proof_inputs[j] = 1;
        } else {
            proof_inputs[j] = 0;
        }
        j += 1;
        for (uint256 i = 3; i >= 0; --i) {
            proof_inputs[j] =
                uint256(serialNumber >> (i * 32 + 128)) &
                0xffffffff;
            j += 1;
            if (i == 0) {
                break;
            }
        }
        for (uint256 c_index = 0; c_index < 10; c_index++) {
            bytes32 commit = commitsForProof[c_index];
            for (uint256 i = 7; i >= 0; i--) {
                proof_inputs[j] = uint256(commit >> (i * 32)) & 0xffffffff;
                j += 1;
                if (i == 0) {
                    break;
                }
            }
        }

        Verifier v = Verifier(verifierContractAddress);
        require(v.verifyTx(proof, proof_inputs));

        // is commitsForProof subset of commits
        for (uint256 i = 0; i < commitsForProof.length; ++i) {
            bytes32 commitInProof = commitsForProof[i];
            if (commitInProof != 0) {
                require(commits[commitInProof]);
            }
        }

        require(!seenSerialNumbers[serialNumber], "Already revealed!");
        seenSerialNumbers[serialNumber] = true;

        if (_vote) {
            yesCount += 1;
        }
        voteCount += 1;
    }
}

interface Verifier {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    struct Proof {
        G1Point a;
        G2Point b;
        G1Point c;
    }

    function verifyTx(Proof memory proof, uint256[85] memory input)
        external
        view
        returns (bool r);

    function testVerifyTx(Proof memory proof, uint256[85] memory input)
        external
        view
        returns (bool r);
}
