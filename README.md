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

Finally for the purposes of this example, we simply compare the data to encrypt with the decrypted data. Note that any data is automatically cast to a `Buffer`, so we should expect that the decrypted data will be a buffer even if we passed in a string; this is why we explicitly cast the data to be encrypted to a buffer then back to a string for this test; this ensures we are dealing with strings with the same `utf8` encoding for the comparison.

## Requesting passphrases from the user

As mentioned above, we can provide a function instead of strings for the passphrase arguments. In this case the function should return a promise so that we can keep the operations asynchronous while the user enters their passphrase.

The following function is used by the tests in `src/test.js` to obtain a password from the console:

```javascript
function getpassphrase(prompt = "Enter your passphrase: ") {
    return new Promise((resolve, reject) => {
        // Adapted from https://stackoverflow.com/a/59727173/2946845
        var readline = require("readline"),
            rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        rl.input.on("keypress", (c, k) => {
        // get the number of characters entered so far:
        var len = rl.line.length;
        // move cursor back to the beginning of the input:
        readline.moveCursor(rl.output, -len, 0);
        // clear everything to the right of the cursor:
        readline.clearLine(rl.output, 1);
        // replace the original input with asterisks:
        for (var i = 0; i < len; i++) {
            rl.output.write("*");
        }
        });
        rl.question(prompt, pw => {
            resolve(pw);
            rl.close();
        });
    });
}
```

We can provide this function as parameters when we initialise `CryptClient`:

```javascript
CryptClient.init(
  'my.keyfile', 
  () => getpassphrase("Enter your key file passphrase: "),
  () => getpassphrase("Enter your private key passphrase: ")
).then( client => {
  // We can now use client to encrypt or decrypt data
}).catch( err => {
  // Something went wrong, possibly an incorrect passphrase - err contains the actual error/exception that occured
});
```

The above code will always request a key file passphrase, as this is needed to create a new key pair or decrypt an existing one. The private key passphrase will only be requested if we are generating a new key pair, as decrypting an existing key pair does not require a private key passphrase.

We can also do the same when decrypting; lets assume we already have `encryptedKey` and `encryptedData` to decrypt:

```javascript
CryptClient.init(
  'my.keyfile', 
  () => getpassphrase("Enter your key file passphrase: ")
).then( client => {
  client.decrypt(
    encryptedKey, 
    encryptedData, 
    () => getpassphrase("Enter your private key passphrase: ")
  ).then( decryptedData => {
    // We now have the decryptedData
  }).catch( err => {
    // Something went wrong during decryption, possibly an incorrect passphrase - err contains the actual error/exception that occured
  });
}).catch( err => {
  // Something went wrong during initialisation, possibly an incorrect passphrase - err contains the actual error/exception that occured
});
```

Note that this example does not include a *private key passphrase* in the call to `CryptClient.init` because we don't expect to need it; if we are trying to decrypt data then the key pair must already exist, so the parameter won't be used anyway.

You can, however, see that the passphrase will be requested to decrypt the data. If a private key passphrase wasn't set when the keys were generated this won't be used, as the passphrase is already known from the key file. If a passphrase is needed, however, the user will be required to enter it.
