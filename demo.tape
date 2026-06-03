# vhs tape for sigma-forge — render with: vhs demo.tape
# Produces docs/images/demo.gif
Output docs/images/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 880
Set Theme "GitHub Dark"
Set Padding 20
Set TypingSpeed 30ms

Type "# sigma-forge: author Sigma -> Splunk SPL + Sentinel KQL, fire-tested in CI"
Enter
Sleep 1500ms

Type "sigma-forge convert rules/classic/win_encoded_powershell.yml -t splunk"
Enter
Sleep 3s

Type "sigma-forge evaluate --all"
Enter
Sleep 3500ms

Type "sigma-forge coverage"
Enter
Sleep 2500ms

Type "make test"
Enter
Sleep 4500ms
