# go-acme

communicate with let's encrypt using acme protocol, temporary only support DNS-Challenge

## first-time

```bash
# generate a key pair for register
$ ssh-keygen -t rsa -b 4096 -C "<your email>" -f letsencrypt -N ''

# configure config.yml
serverPrivateKeyPath: <your private key file path>
accountConfigPath: <which place you want to save account info>
certSavePath: <which place you want to save certs>
```
