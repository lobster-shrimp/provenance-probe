Output docs/media/unmask-cn-model.gif
Set Shell "bash"
Set FontSize 15
Set Width 1200
Set Height 800
Set Theme "Catppuccin Mocha"
Set TypingSpeed 32ms
Set Padding 20

Hide
Type "export VIRTUAL_ENV_DISABLE_PROMPT=1; source .venv/bin/activate; export PS1='\[\e[35m\]probe\[\e[0m\] $ '; clear"
Enter
Sleep 1s
Show

Type "# A vendor sells you 'northstar-secure-1' — sounds like a safe US model."
Enter
Sleep 1800ms
Type "# What's ACTUALLY serving it? Fingerprint the tokenizer. No API key needed."
Enter
Sleep 1800ms
Type "provenance-probe assess --config docs/media/demo-target.json --i-am-authorized --no-behavioral"
Enter
Sleep 22s
