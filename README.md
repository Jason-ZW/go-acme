# go-acme

communicate with let's encrypt using acme protocol

## first-time

```bash
# generate a key pair for our account
$ ssh-keygen -t rsa -b 4096 -C "<your email>" -f letsencrypt -N ''

# configure config.yml
serverPrivateKeyPath: <your private key file path>
```
