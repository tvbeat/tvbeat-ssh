`tvbeat-ssh` - a small helper script to grant you ssh access to tvbeat systems

**prerequisites**

- the `vault` binary [installed](https://developer.hashicorp.com/vault/docs/install) on your system
- basic system utilities such as `grep`, `jq`, `sed`, and `ssh` installed on your system
  - if you are a mac user please install gnu `date` and gnu `sed` via `brew`

**installation**

- copy the `tvbeat-ssh` script to your `$PATH`
- run `tvbeat-ssh validate` to ensure your install was successful
- run `tvbeat-ssh config <username>` to configure your ssh client, where `<username>` is your username on all of our linux systems

```console
aanderse@ubuntu:~$ sudo curl -f -o /usr/local/bin/tvbeat-ssh https://raw.githubusercontent.com/tvbeat/tvbeat-ssh/master/tvbeat-ssh
aanderse@ubuntu:~$ sudo chmod +x /usr/local/bin/tvbeat-ssh
aanderse@ubuntu:~$ tvbeat-ssh validate
checking availability of required dependencies:

- [✔] grep
- [✔] jq
- [✔] scp
- [✔] sed
- [✔] ssh
- [✔] vault
aanderse@ubuntu:~$ tvbeat-ssh config aanderse
aanderse@ubuntu:~$ # all done
```

**usage**

- you can ssh into any of the `dev0-hetz` servers as usual, though occasionally a web browser will pop up and confirm your identity:

```console
aanderse@ubuntu:~$ ssh dev0-hetz+scoria.node
Complete the login via your OIDC provider. Launching browser to:

    https://accounts.google.com/o/oauth2/v2/auth?client_id=868626873714-t4gavvk1721sfrle0onaa8o2s1allh91.apps.googleusercontent.com&code_challenge=liTD6-G_e-CQNINLWrL_Z0yfurUzI0hV57FxQ0LeMO4&code_challenge_method=S256&nonce=n_BAiOHOKaNa0Z40eDB8bo&redirect_uri=http%3A%2F%2Flocalhost%3A8250%2Foidc%2Fcallback&response_type=code&scope=openid+profile+email&state=st_izd1XP4Ctj0FxTtvKsD4


Waiting for OIDC authentication to complete...
Last login: Thu Oct  5 00:58:33 2023

[aanderse@scoria:~]$ # easy peasy

```

**conclusion**

special care was taken to make this utility an unobtrusive as possible after initial installation and configuration
