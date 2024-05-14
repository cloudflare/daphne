#! /bin/bash

# if no tmux stop
if ! which tmux > /dev/null; then
    echo "missing tmux, please install before continuing"
    exit 8840
fi


# key setup
make /tmp/private-key /tmp/certificate
export DAP_SERVICE__SIGNING_KEY="$(cat /tmp/private-key)"; \

echo 'signing key:'
echo $DAP_SERVICE__SIGNING_KEY
echo


# configuration
read -r -d '' TMUX_CONFIG << EOC
set-window-option -g mouse on; 
set-option -g default-terminal "xterm-256color";
set-window-option -g xterm-keys on;
set-option -g history-limit 30000;
set-option -g pane-border-style fg=colour237;
set-option -g pane-active-border-style fg=colour241;
set-option -g window-style bg=black;
set-option -g window-active-style bg=colour237;
set-option -g status-justify left;
set-option -g status-interval 2;
set-option -g visual-activity off;
set-option -g visual-bell off;
set-option -g visual-silence off;
set-window-option -g monitor-activity off;
set-option -g bell-action none;
set-option -g pane-border-status;
set-option -g status off;
EOC

tmux new-session -d bash;
tmux send -t 0:0.0 "trap \"docker stop daphne-server-leader_storage; docker stop daphne-server-helper_storage; tmux kill-window\" EXIT && clear " Enter
# set configuration for running server
tmux ${TMUX_CONFIG}

tmux split-window -v bash
tmux split-window -v bash
tmux split-window -h bash
tmux select-pane -t %1
tmux split-window -h bash

tmux send -t 0:0.1 "printf '\033]2;%s\033\\' 'leader storage'; docker run --rm --name daphne-server-leader_storage -p 4000:4000 daphne-server-leader_storage --port=4000" C-m
tmux send -t 0:0.2 "printf '\033]2;%s\033\\' 'leader'; make leader" C-m
tmux send -t 0:0.3 "printf '\033]2;%s\033\\' 'helper storage'; docker run --rm --name daphne-server-helper_storage -p 4001:4001 daphne-server-helper_storage --port=4001" C-m
tmux send -t 0:0.4 "printf '\033]2;%s\033\\' 'helper'; make helper" C-m

tmux select-pane -t %0

tmux -2 attach-session -d
