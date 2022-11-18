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

    constructor() {
        chairperson = msg.sender;

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

    function revealVote(bool vote, bytes32 serialNumber, bytes32[] commitsForProof, bytes32 proof) public {
        // validate proof
        // call sokrates

        // is commitsForProof subset of commits
        for (uint i = 0; i < commitsForProof.length; ++i) {
            bytes32 commitInProof = commitsForProof[i];
            if (commitInProof != 0) {
                require(commits[commitInProof]);
            }
            
        }

        require(!seenSerialNumbers[serialNumber], "Already revealed!");
        seenSerialNumbers[serialNumber] = true; 


        if (vote) {
            yesCount += 1;
        }
        voteCount += 1;

    }



}