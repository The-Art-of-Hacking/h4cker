# GPG: Generating Keys, Encrypting, and Decrypting Files

The following are step-by-step instructions on how to generate GPG keys, and how to use them to encrypt and decrypt files:

## Generating GPG Keys

- Install GPG: If you haven't already, install GPG on your computer. You can do this by following the installation instructions for your operating system.
- Open your terminal: Open your terminal (or command prompt, for Windows) and enter the following command to generate a new GPG key pair:
```
gpg --full-generate-key
```

- Choose key type: Choose the key type you want to generate. For most purposes, RSA is a good choice.
- Choose key size: Choose the key size you want to generate. Higher than 2048 bits is the recommended minimum for RSA keys.
- Choose key expiry: Choose when you want the key to expire. It's a good idea to set an expiry date so that you can update your keys regularly.
- Enter your name and email: Enter your name and email address. These will be associated with your GPG key.
- Enter passphrase: Enter a passphrase to protect your key. This passphrase is used to decrypt your private key and should be kept secret.
- Save your key: Once your key is generated, you'll see a message that it has been created. Your public key will be stored in a file with a .asc extension in your home directory, and your private key will be stored in your GPG keyring.

## Encrypting and Decrypting Files

- Encrypt a file: To encrypt a file, use the `gpg --encrypt` command followed by the name of the file you want to encrypt. For example:
```
gpg --encrypt file1.txt
```
This will create a new encrypted file with a .gpg extension.

- Decrypt a file: To decrypt a file, use the `gpg --decrypt` command followed by the name of the encrypted file. For example:
```
gpg --decrypt file1.txt.gpg
```

This will decrypt the file and create a new unencrypted file with the original name.

**Note:** When encrypting a file, you can specify the recipient of the encrypted file using the `--recipient` option followed by the email address associated with their public key. For example:

```
gpg --encrypt --recipient omar@example.com file1.txt
```

This will encrypt the file and make it readable only by Omar, whose public key is associated with the email address omar@example.com.

That's it! You now know how to generate GPG keys and use them to encrypt and decrypt files.
