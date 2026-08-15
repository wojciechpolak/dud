Output docs/assets/peer-git-sync.gif

Require tmux

Set Shell "bash"
Set FontSize 18
Set Width 1700
Set Height 600
Set Framerate 12
Set Theme "Catppuccin Frappe"
Set Padding 18
Set Margin 12
Set MarginFill "#1e1e2e"
Set WindowBar Rings
Set WindowBarSize 34
Set TypingSpeed 38ms
Set WaitTimeout 20s

Hide
Type "tmux kill-session -t dud-demo 2>/dev/null || true"
Enter
Type "tmux new-session -d -s dud-demo -x 150 -y 30"
Enter
Type "tmux split-window -h -t dud-demo:0"
Enter
Type "tmux set-option -t dud-demo status off"
Enter
Type "tmux set-option -t dud-demo pane-border-status top"
Enter
Type "tmux set-option -t dud-demo pane-border-format ' #{pane_title} '"
Enter
Type "tmux select-pane -t dud-demo:0.0 -T desktop"
Enter
Type "tmux select-pane -t dud-demo:0.1 -T laptop"
Enter
Type "tmux select-pane -t dud-demo:0.0"
Enter
Type "tmux attach -t dud-demo"
Enter
Type "alias dud=$DUD_DEMO_SHIM"
Enter
Type "export DUD_PROFILE=desktop"
Enter
Type "export PROMPT='%F{81}desktop%f $ '"
Enter
Ctrl+B
Right
Type "alias dud=$DUD_DEMO_SHIM"
Enter
Type "export DUD_PROFILE=laptop"
Enter
Type "export PROMPT='%F{114}laptop%f $ '"
Enter
Ctrl+B
Left
Type "clear"
Enter
Ctrl+B
Right
Type "clear"
Enter
Ctrl+B
Left
Show
Sleep 1s

Type "dud git push laptop --current"
Enter
Wait+Screen /Sent complete Git checkpoint to laptop as data sequence [0-9]+\./
Sleep 1s

Ctrl+B
Right
Type "dud git fetch desktop --associate"
Enter
Wait+Screen /Fetched complete Git checkpoint into refs\/remotes\/desktop\/\*\./
Sleep 6s
