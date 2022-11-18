// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

contract Ballot {

    struct Voter {
        bool hasRightToVote;
        bool voted;  // if true, that person already voted
    }

    struct Proposal {
        // If you can limit the length to a certain number of bytes, 
        // always use one of bytes1 to bytes32 because they are much cheaper
        bytes32 name;   // short name (up to 32 bytes)
        uint voteCount; // number of accumulated votes
    }

    address public chairperson;
    mapping(address => Voter) public voters;
    mapping(bytes32 => bool) public commits;
    mapping(bytes32 => bool) public seenSerialNumbers;
    uint public yesCount;
    uint public voteCount;
    address public verifierContractAddress;

    constructor(address _verifierContractAddress) {
        chairperson = msg.sender;
        verifierContractAddress = _verifierContractAddress;

        voters[chairperson] = Voter({
            hasRightToVote: true,
            voted: false
        });
    }

    function giveRightToVote(address voter) public {
        require(
            msg.sender == chairperson,
            "Only chairperson can give right to vote."
        );
        require(
            !voters[voter].voted,
            "The voter already voted."
        );
        require(voters[voter].hasRightToVote == false);
        voters[voter].hasRightToVote = true;
    }


    function vote(bytes32 commit) public {
        Voter storage sender = voters[msg.sender];
        require(sender.hasRightToVote, "Has no right to vote");
        require(!sender.voted, "Already voted.");
        sender.voted = true;

        commits[commit] = true;
    }

    function revealVote(bool _vote, bytes32 serialNumber, bytes32[10] memory commitsForProof, uint proof) public {
        // validate proof
        // call sokrates
        // uint[85] memory proof_inputs;
        // uint j = 0;
        // if (_vote) {
        //     proof_inputs[j] = 1;
        // } else {
        //     proof_inputs[j] = 0;
        // }
        // j += 1;
        // for(uint i = 0; i < 4; i++) {
        //     proof_inputs[j] = serialNumber[i];
        //     j += 1;
        // }
        // for(uint i = 0; i < 80; i++) {
        //     proof_inputs[j] = commitsForProof[i];
        //     j += 1;
        // }
        //Verifier v = Verifier(verifierContractAddress);
        //require(v.test(proof));

        // is commitsForProof subset of commits
        for (uint i = 0; i < commitsForProof.length; ++i) {
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

    function testVerifyTx(Verifier.Proof memory proof, uint[85] memory input) public {
        Verifier v = Verifier(verifierContractAddress);
        require(v.testVerifyTx(proof, input));
    }

}


interface Verifier {


    struct G1Point {
        uint X;
        uint Y;
    }

    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }

    struct Proof {
        G1Point a;
        G2Point b;
        G1Point c;
    }

    function verifyTx(Proof memory proof, uint[85] memory input) external view returns (bool r);
    function testVerifyTx(Proof memory proof, uint[85] memory input) external view returns (bool r);
}