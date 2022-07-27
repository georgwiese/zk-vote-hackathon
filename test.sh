# Does a series of votes.
# For this to work, start the server as:
# DEBUG_ALLOW_DOUBLE_VOTING=true FLASK_APP=voting_server FLASK_ENV=development python -m flask run -h 0.0.0.0

for i in {1..15}
do
    if ! ((i % 3))
    then
        vote=yes
    else
        vote=no
    fi
    echo "=== Vote $i: $vote"
    python src/vote_cli.py vote $vote
    python src/vote_cli.py reveal
done