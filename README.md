# ACME Register

This repository aim to automation register an ACME account using Google Public CA (beta) by EAB method.

## Usage 

```console
$ acme-register --help

Register an ACME account via External Account Binding (EAB).
If the eab flags is not specified, this will create a new one via Google Public CA.

Permission required:
* publicca.externalAccountKeys.create

NOTES:
* Make sure that, google cloud already authenticated in this machine.
* Public CA API must be enabled. To enable: 'gcloud services enable publicca.googleapis.com'.
* The input private key must have RSA PKCS#8 format.

Usage:
  acme-register [flags]

Flags:
      --bits int                  The bit size for new Private Key. This only be used when --private-key-path is not specified. Bit size must be >= 512 and <= 4096. (default 2048)
      --eab string                External Account Binding. If this not specified, the program will create a new one via google public CA. If specified, --hmac-key will be required.
      --email string              Email to register ACME account. This flag is not required.
  -h, --help                      help for acme-register
      --hmac-key string           B64 HMAC key. This flag is required if --eab is specified.
  -o, --output string             The output format. Supported 'json' and 'yaml'. (default "json")
      --private-key-path string   Private key used for register ACME account. If not specified, this will create a new one.
      --project-id string         Google Cloud Project Id. --eab and --hmac-key are not specified, this flag will be required.
      --staging                   If this flag is presented. This will register with Google CA server on Staging environment.
```

## Notes
* Make sure that, google cloud already authenticated in this machine.
* Public CA API must be enabled. To enable: 'gcloud services enable publicca.googleapis.com'.
* The input private key must have RSA PKCS#8 format.

## References
* https://cloud.google.com/certificate-manager/docs/public-ca
* https://go-acme.github.io/lego/usage/library/
