#!/bin/bash
CHALL_NAME=$1
BASE_DIR=~/ctf/pwn/$CHALL_NAME
SESSION="PWN_$CHALL_NAME"

# Directory creation
if [ -d "$CHALL_NAME" ]; then
    echo "[i] directory exist"
else
    mkdir "$CHALL_NAME"
    cp ~/config_file/template_exploit.py $CHALL_NAME/exploit.py
    cp ~/config_file/template_write_up.md $CHALL_NAME/$CHALL_NAME.md
fi

# TMUX session
tmux new-session -d -s $SESSION -n SRC_CODE
tmux send-keys -t $SESSION:1 "cd $BASE_DIR" Enter

tmux new-window -t $SESSION -n EXPLOIT
tmux send-keys -t $SESSION:2 "cd $BASE_DIR && lvim exploit.py" Enter

tmux new-window -t $SESSION -n SHELL
tmux send-keys -t $SESSION:3 "cd $BASE_DIR && source ../pwn_env/bin/activate" Enter

tmux new-window -t $SESSION -n WRITE_UP
tmux send-keys -t $SESSION:4 "cd $BASE_DIR && lvim $CHALL_NAME.md" Enter

tmux select-window -t $SESSION:1
tmux attach -t $SESSION

# Change session
if [ -n "$TMUX" ]; then
    tmux switch-client -t $SESSION
else
    tmux attach -t $SESSION
fi
