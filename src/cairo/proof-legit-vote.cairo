%builtins output pedersen range_check
from starkware.cairo.common.find_element import find_element
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import (
    HashBuiltin,
    SignatureBuiltin,
)
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.serialize import serialize_word


func parse_inputs() -> (commits : felt*, num_commits: felt, vote : felt, secret: felt, serial_nr: felt):
    alloc_locals
    local vote
    local secret
    local serial_nr
    local num_commits 
    local commits : felt*

    %{
        ids.vote = program_input['vote']
        ids.secret = program_input['secret']
        ids.serial_nr = program_input['serial_nr']
        ids.num_commits = len(program_input['commits'])

        ids.commits = commits = segments.add()
        for i, commit in enumerate(program_input['commits']):
            memory[commits + i] = commit
                
    %}
    return (commits=commits, num_commits=num_commits, vote=vote, secret=secret, serial_nr=serial_nr)
end

func print_commits{output_ptr: felt*}(commits: felt*, size: felt) -> ():
    if size == 0:
        return ()
    end
    serialize_word([commits])
    print_commits(commits = commits + 1, size = size - 1)
    return ()
end

func main{output_ptr: felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    alloc_locals
    let(local commits, num_commits, local vote, secret, local serial_nr) = parse_inputs()

    let (hash_1) = hash2{hash_ptr=pedersen_ptr}(x=serial_nr, y=secret)
    let (commit) = hash2{hash_ptr=pedersen_ptr}(x=vote, y=hash_1)

    let (element_ptr : felt*) = find_element(
        array_ptr=commits,
        elm_size=1,
        n_elms=num_commits,
        key=commit,
    )
    print_commits(commits, num_commits)
    serialize_word(vote)
    serialize_word(serial_nr)
    return ()
end