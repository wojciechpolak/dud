Output docs/assets/peer-overview.gif

Require tmux

Set Shell "bash"
Set FontSize 18
Set Width 1700
Set Height 900
Set Framerate 12
Set Theme "Catppuccin Frappe"
Set Padding 18
Set Margin 12
Set MarginFill "#1e1e2e"
Set WindowBar Rings
Set WindowBarSize 34
Set TypingSpeed 38ms
Set WaitTimeout 30s

Hide
Type "tmux kill-session -t dud-demo 2>/dev/null || true"
Enter
Type "tmux new-session -d -s dud-demo -x 150 -y 40"
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
Type "export DUD_DEMO_AUTO_ACCEPT=1"
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

Type "dud peer invite laptop"
Enter
Wait+Screen /Pairing code: [0-9a-f-]+/
Sleep 2s

Ctrl+B
Right
Type "dud peer accept desktop"
Enter
Wait+Screen /Peer "desktop" is active after mutual pairing-code authentication\./
Sleep 1s

Hide
Type "clear"
Enter
Ctrl+B
Left
Type "clear"
Enter
Show
Sleep 1s

Type "dud send laptop --file briefing.txt"
Enter
Wait+Screen /Sent to laptop as data sequence [0-9]+\./
Sleep 1s

Ctrl+B
Right
Type "dud receive desktop --out-dir received"
Enter
Wait+Screen /Received data sequence [0-9]+ from desktop at \/work\/received\/briefing\.txt\./
Sleep 5s
