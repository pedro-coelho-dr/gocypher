# gocypher

`gocypher` is a simple practice project in Go focused on cryptography, using AES-GCM for encryption and decryption.

```console
go build -o gocypher
```
```console
./gocypher encrypt mypassword "plaintext"
```

```console
./gocypher decrypt mypassword salt cyphertext
```