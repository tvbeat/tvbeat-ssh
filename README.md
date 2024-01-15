`tvbeat-ssh` - a small helper script to grant you ssh access to tvbeat systems

**installation**

- [download](https://github.com/tvbeat/tvbeat-ssh/releases) and copy the `tvbeat-ssh` executable to your `$PATH`
- run `tvbeat-ssh config --username <username>` to configure your ssh client, where `<username>` is your username on all of our linux systems

```console
aanderse@ubuntu:~$ sudo mv ~/Downloads/tvbeat-ssh /usr/local/bin/tvbeat-ssh
aanderse@ubuntu:~$ tvbeat-ssh config --username aanderse
/home/aaron/.ssh/tvbeat.conf has been successfully generated.
aanderse@ubuntu:~$ # all done
```

**usage**

- you can ssh into any of the `dev0-hetz` servers as usual, though occasionally a web browser will pop up and confirm your identity:

```console
aanderse@ubuntu:~$ ssh dev0-hetz+scoria.node
Last login: Thu Oct  5 00:58:33 2023

[aanderse@scoria:~]$ # easy peasy

```

**conclusion**

special care was taken to make this utility an unobtrusive as possible
