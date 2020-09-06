# 🔐 node-crypt-client 🔐

:exclamation: **This package is under intial development; please do not attempt to use this as a package in your node applications just yet. This is my first time attempting to provide a package you can import into your own application, so please bear with me - once I have confirmed this works as a package I will remove this warning!**

This package implements aes-256-cbc encryption of arbitrary data secured with RSA public key encryption (using node's built in `crypto` module), and provides a promise-based interface.

## Main Features

* Public and private key generation
* Secure storage of generated keys
* Encryption using public key
* Decryption using private key (protected with an optional passphrase
* All methods are asynchronous, implemented using promises

## Process Overview

Operations can be broadly split into three processes:

* Key Generation Process
  * The user software uses this package to generate a public and private key; it is recommended that the user provides a *private key passphrase* as an extra layer of security when it comes to decrypting data.
  * The key pair is encrypted with a *key file passphrase*, using `aes-256-cbc`encryption
  * The encrypted key pair is stored to disk; this is kept private and should never be shared, but the encryption of these keys acts as an extra layer of security if, for example, the computer on which the keys are stored is stolen or attacked.
  * The public key can be transferred to a third party - this is then used by the data encryption process below

* Data Encryption Process
  * The third party is given the public key by the user, and they store this to encrypt data that is only to be read by that user
  * When data needs to be stored, a random secure passphrase is generated for that specific dataset.
  * The data is encrypted with the random secure passphrase, and the passphrase itself is then encrypted with the user's public key using `rsa public key` encryption.
  * The encrypted data and the encrypted passphrase are then kept together
  * The encrypted data/passphrase pair can then be used by the data decryption process below

* Data Decryption Process
  * The user loads their encrypted keys, using their given *key file passphrase* to obtain the private key
  * The user retrieves the encrypted data and encrypted passphrase from the third party
  * The user provides their *private key passphrase* and uses this to decrypt the encrypted passphrase retrieved with the data
  * The user then uses the decrypted passphrase to decrypt the data

## Why is this necessary?

We have a web server which obtains data on behalf of a registered user; this server needs to store data in an encrypted form so that an attacker who gains access to the server cannot obtain this private (and potentially sensitive) data.

The registered user has an application which uses this package to generate a key pair and store it securely, so that even if the machine is stolen or compromised, there is an extra layer of security preventing the attacker from obtaining the private key.

The server is given a copy of the public key which is stored against the registered user's records. This can then be used to encrypt each submitted dataset so that the data can only be decrypted by the user on their own device; at no point can the server retrieve or process the encrypted data, so it is safe from any attacker to that server (or unscrupulous admins, etc).

The user's data is therefore always kept secure from the point of storage all the way through to the point the data is received by the user for whom it is intended.

# Basic usage

Here is a contrived example showing the three process described above:

```javascript
const CryptClient = require('node-crypt-client');
const dataToEncrypt="This is the data to be encrypted!";
const keyFilePassphrase="Passphrase provided by user to protect their stored key pair";
const privateKeyPassphrase="Passphrase provided by user to protect their encrypted data";

CryptClient.init('my.keyfile', keyFilePassphrase, privateKeyPassphrase).then( client => {
  client.encrypt(dataToEncrypt).then( ([encryptedKey, encryptedData]) => {
    client.decrypt(encryptedKey, encryptedData, privateKeyPassphrase).then( decryptedData => {
      if(Buffer.from(dataToEncrypt).toString('utf8') == decryptedData.toString('utf8') {
        console.log("Data encrypted and decrypted successfully!");
      } else {
        console.log("Data changed during encryption/decryption process!");
    }).catch(err => console.warn(%o\nDecryption failed", err));
  }).catch(err => console.warn("%o\nEncryption failed", err));
}).catch( err => console.warn("%o\nFailed to initialise CryptClient", err));
```

Lets deconstruct this example. First we call `CryptClient.init` providing a filename (in which our encrypted keys are stored) along with the *key file passphrase* and the *private key passphrase*. The first time this is called, a public and private key will be generated using these passphrases and it will be stored in the given filename ('my.keyfile' in this case). Subsequent calls will instead *load* the given keyfile and decrypt it with the *key file passphrase*. The promise is resolved, providing an instance of the `CryptClient` class (`client`).

It's worth noting that we have hard-coded the passphrases and the data to be encrypted in this example, but of course these details would not normally be a part of the code; in particular the passphrases would be entered by the user rather than being stored anywhere - we can actually provide functions rather than strings as the passphrase parameters to aid retrieving them from the user, but more on that later.

Next we encrypt some data using `client.encrypt`. This resolves the promise providing the encrypted data key and the encrypted data; at this point we would ordinarily store both of these together in a database record.

Next we decrypt the data again using `client.decrypt`. Note that the *private key passphrase* is required if one is set; if no *private key passphrase* was given when the keys were generated, a random one is generated and stored along with the keys, so you can omit the *private key passphrase* although it is recommended that you provide one.
