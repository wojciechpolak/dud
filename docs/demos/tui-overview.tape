Output docs/assets/tui-overview.gif

Set Shell "bash"
Set FontSize 18
Set Width 1400
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
Type `cd "$DUD_DEMO_WORK"`
Enter
Type "export PS1='demo $ '"
Enter
Type "clear"
Enter
Show
Type "dud --tui"
Enter
Wait+Screen /7\) tools/
Sleep 3s

# Explore the dead drop form without making a network request.
Type "1"
Wait+Screen /Share by opaque ID/
Sleep 3s
Enter
Wait+Screen /Send message/
Sleep 2s
Enter
Wait+Screen /Lifetime/
Sleep 1s
Type "A private message"
Sleep 5s
Escape
Sleep 1s
Escape
Sleep 1s

# Optical sending is available without initializing a peer device.
Down
Sleep 3s
Enter
Wait+Screen /Send message/
Sleep 2s
Down
Sleep 1s
Enter
Wait+Screen /QR profile/
Sleep 2s
Type "briefing.txt"
Tab
Tab
Right
Sleep 5s
Escape
Sleep 1s
Escape
Sleep 1s
Escape
Wait+Screen /7\) tools/
Sleep 1s

Type "7"
Wait+Screen /decrypt optical capsule/
Sleep 3s
Enter
Wait+Screen /Extract a collection/
Sleep 5s
Escape
Sleep 1s
Escape
Wait+Screen /7\) tools/
Sleep 1s

Type "4"
Wait+Screen /create invitation/
Sleep 4s
Escape
Wait+Screen /7\) tools/
Sleep 1s
Type "3"
Wait+Screen /Import a checkpoint/
Sleep 4s
Escape
Wait+Screen /7\) tools/
Sleep 1s
Type "q"
Sleep 1s
