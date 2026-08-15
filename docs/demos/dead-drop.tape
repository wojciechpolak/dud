Output docs/assets/dead-drop.gif

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
Type "tmux select-pane -t dud-demo:0.0 -T sender"
Enter
Type "tmux select-pane -t dud-demo:0.1 -T recipient"
Enter
Type "tmux select-pane -t dud-demo:0.0"
Enter
Type "tmux attach -t dud-demo"
Enter
Type "alias dud=$DUD_DEMO_DROP_SHIM"
Enter
Type "export DUD_DEMO_SIDE=desktop"
Enter
Type "export PROMPT='%F{215}sender%f $ '"
Enter
Type `export D="$DUD_DEMO_SHARED_WORK/.d"`
Enter
Ctrl+B
Right
Type "alias dud=$DUD_DEMO_DROP_SHIM"
Enter
Type "export DUD_DEMO_SIDE=laptop"
Enter
Type "export PROMPT='%F{114}recipient%f $ '"
Enter
Type `export D="$DUD_DEMO_SHARED_WORK/.d"`
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

Type "dud upload --file briefing.txt -R recipient.txt|tee $D"
Enter
Wait+Screen /QR Code:/
Sleep 1s

Ctrl+B
Right
Hide
Type `id=$(awk '$1 == "ID" { print $2; exit }' $D)`
Enter
Type `tmux send-keys -t dud-demo:0.1 -l "dud download --id $id -i recipient.key --stdout"`
Enter
Ctrl+L
Show
Sleep 1s
Enter
Wait+Screen /Encrypted briefing for the demo\./
Sleep 6s
