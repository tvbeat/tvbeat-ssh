`tvbeat-ssh` - a small tool to grant you ssh access to tvbeat systems

after successfully installing `tvbeat-ssh` you can forget about this tool entirely - `tvbeat-ssh` will seamlessly work behind the scenes to grant you ssh access to tvbeat systems without you explicitly having to do anything

**installation & configuration**

- [download](https://github.com/tvbeat/tvbeat-ssh/releases), extract, and copy the `tvbeat-ssh` executable to your `$PATH`
- run `tvbeat-ssh config --username <username>` to configure your ssh client, where `<username>` is your username on all of our linux systems

**installation - darwin**

```console
aanderse@macbook ~ % curl -O https://github.com/tvbeat/tvbeat-ssh/releases/download/v1.0.1/tvbeat-ssh-v1.0.1-darwin-amd64.tar.gz
aanderse@macbook ~ % tar xf tvbeat-ssh-v1.0.1-darwin-amd64.tar.gz
aanderse@macbook ~ % sudo mkdir /usr/local/bin/
aanderse@macbook ~ % sudo mv tvbeat-ssh /usr/local/bin/
aanderse@macbook ~ % tvbeat-ssh config --username aanderse
/Users/aanderse/.ssh/tvbeat.conf has been successfully generated.
aanderse@macbook ~ % # all done
```
You might get a popup window saying the `tvbeat-ssh` program cannot be run. On the popup window you should click the `Show in Finder` button, and once the `Finder` window is opened, right-click the `tvbeat-ssh` program and click `Open`. This will ensure `tvbeat-ssh` can run at any point in the future.

You can now repeat the `tvbeat-ssh` configuration command and everything should work:
```
aanderse@macbook ~ % tvbeat-ssh config --username aanderse
/Users/aanderse/.ssh/tvbeat.conf has been successfully generated.
aanderse@macbook ~ % # all done
```

**installation - linux**

```console
aanderse@ubuntu:~$ wget https://github.com/tvbeat/tvbeat-ssh/releases/download/v1.0.1/tvbeat-ssh-v1.0.1-linux-amd64.tar.gz
aanderse@ubuntu:~$ tar xf tvbeat-ssh-v1.0.1-linux-amd64.tar.gz
aanderse@ubuntu:~$ sudo mv tvbeat-ssh /usr/local/bin/
aanderse@ubuntu:~$ tvbeat-ssh config --username aanderse
/home/aanderse/.ssh/tvbeat.conf has been successfully generated.
aanderse@ubuntu:~$ # all done
```

**installation - windows**

*NOTE:* the following assumes you are in a `powershell` terminal, though [can be adapted](https://jonathansoma.com/lede/foundations-2019/terminal/adding-to-your-path-cmder-win/) for console emulators like `cmder`

```console
PS C:\Users\aanderse> Invoke-WebRequest -Uri https://github.com/tvbeat/tvbeat-ssh/releases/download/v1.0.1/tvbeat-ssh-v1.0.1-windows-amd64.zip -OutFile tvbeat-ssh-v1.0.1-windows-amd64.zip
PS C:\Users\aanderse> New-Item -ItemType directory -Path "$env:USERPROFILE\bin" -Force
PS C:\Users\aanderse> Expand-Archive -Path tvbeat-ssh-v1.0.1-windows-amd64.zip -DestinationPath "$env:USERPROFILE\bin\" -Force
PS C:\Users\aanderse> [Environment]::SetEnvironmentVariable("PATH", [Environment]::GetEnvironmentVariable("PATH", "USER") + ";$env:USERPROFILE\bin", "USER")
PS C:\Users\aanderse> # at this point exit powershell, then enter again to refresh your $PATH
PS C:\Users\aanderse> tvbeat-ssh config --username aanderse
C:\Users\aanderse\.ssh\tvbeat.conf has been successfully generated.
PS C:\Users\aanderse> # all done
```

**usage**

you can ssh into any of the `dev0-hetz` servers (like `slate.node`, `scoria.node`, `onix.node`, etc...) as usual, though occasionally a web browser will pop up and confirm your identity:

```console
aanderse@ubuntu:~$ ssh dev0-hetz+scoria.node
Last login: Thu Oct  5 00:58:33 2023

[aanderse@scoria:~]$ # easy peasy

```

**conclusion**

special care was taken to make this utility an unobtrusive as possible
