// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

contract Ballot {

    struct Voter {
        bool has_vote_right;
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
    uint public yes_counts;
    uint public vote_counts;

    constructor() {
        chairperson = msg.sender;

        voters[chairperson] = Voter({
            has_vote_right: true,
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
        require(voters[voter].has_vote_right == false);
        voters[voter].has_vote_right = true;
    }


    function vote(bool has_voted_yes) public {
        Voter storage sender = voters[msg.sender];
        require(sender.has_vote_right, "Has no right to vote");
        require(!sender.voted, "Already voted.");
        sender.voted = true;

        if (has_voted_yes) {
            yes_counts += 1;
        }
        vote_counts += 1;
    }

}