import crypto from 'crypto';
import fs from 'fs';

export default class CryptClient {
    constructor(keyFileName) {
        this.keyFileName = keyFileName
    }

    /**
     * init
     * 
     * Initialise & instantiate a new instance of this class, using the given keyFile
     * and passphrases.
     * 
     * On success, the returned promise is resolved with the instance of CryptClient,
     * otherwise the promise is rejected  with the error details
     * 
     * @param {string} keyFile 
     * @param {string} keyFilePassphrase 
     * @param {string} privateKeyPassphrase 
     * @returns {Promise}
     */
    static init(keyFile, keyFilePassphrase, privateKeyPassphrase = null) {
        return new Promise(
            (resolve, reject) => {
                const instance = new CryptClient(keyFile);
                fs.access(keyFile, err => {
                    if(err) {
                        const fn = passphrase => {
                            CryptClient.generateKeys(passphrase).then(keys => {
                                instance.keys = keys;
                                instance.setKeyFile(keyFilePassphrase)
                                    .then(() =>resolve(instance))
                                    .catch(err => reject(err));
                            }).catch(err => reject(err));
                        };

                        if( typeof privateKeyPassphrase == "function") {
                            privateKeyPassphrase().then(passphrase => {
                                fn(passphrase);
                            }).catch(err => reject(err));
                        } else {
                            fn(privateKeyPassphrase);
                        }
                    } else {
                        instance.getKeyFile(keyFilePassphrase)
                            .then(keyFile =>resolve(instance))
                            .catch(err => reject(err));
                    }
                });
            }
        )
    } // End of init  

    /**
     * generateKeys
     * 
     * This method generates an RSA key pair, optionally using a given passphrase.
     * If no passphrase is given, a random one will be generated and returned along with the key.
     * 
     * On successful generation the promise is resolved with an object containing privateKey and 
     * publicKey strings, and if a random passphrase was generated a string named passphrase will
     * also be included which will be a hexadecimal representation of the passphrase.
     * 
     * On failure, the promise is rejected with the error details.
     * 
     * @param {string} privateKeyPassphrase 
     * @returns {Promise}
     */
    static generateKeys(privateKeyPassphrase) {
        return new Promise((resolve,reject) => {
            const passphrase = privateKeyPassphrase ?? crypto.randomBytes(32);
            const keys={};
            crypto.generateKeyPair('rsa', {
                modulusLength: 4096,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem',
                    cipher: 'aes-256-cbc',
                    passphrase: passphrase
                }
            }, (err, publicKey, privateKey) => {
                if(err) {
                    reject(err);
                } else {
                    keys.publicKey=publicKey;
                    keys.privateKey=privateKey;
                    if(!privateKeyPassphrase) {
                        keys.passphrase=passphrase.toString("hex");
                    }
                    resolve(keys);
                }
            });
        });
    }

    /**
     * encryptKeys
     * 
     * This encrypts the given keys object (as returned by generateKeys above) using the 
     * given password. This allows safe(r) storage of the keys as the password is needed
     * to decrypt the keys again.
     * 
     * On success, the promise is resolved with a Buffer containing the encrypted keys.
     * 
     * @param {object} keys 
     * @param {string} keyFilePassphrase 
     * @returns {Promise}
     */
    static encryptKeys(keys, keyFilePassphrase) {
        return new Promise( (resolve, reject) => {
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv('aes-256-cbc', crypto.createHash('sha256').update(keyFilePassphrase, 'binary').digest(), iv );
            let encrypted = '';
            cipher.on('readable', () => {
                let chunk;
                while (null !== (chunk = cipher.read())) { 
                    encrypted += chunk.toString('hex'); 
                } 
            });
            cipher.on('end',() => {
                const output = iv.toString('hex') + encrypted;
                resolve(Buffer.from(output, 'hex'));
            });
            cipher.write(JSON.stringify(keys));
            cipher.end();
        });
    }

    /**
     * decryptKeys
     * 
     * This decrypts the given Buffer (as returned by encryptKeys) back to an object.
     * 
     * On success, the promise is resolved with an object containing privateKey, publicKey
     * and (possibly) the passphrase encoded in hexadecimal
     * 
     * @param {Buffer|string} encryptedKeys 
     * @param {string} keyFilePassphrase 
     * @returns {Promise}
     */
    static decryptKeys(encryptedKeys, keyFilePassphrase) {
        return new Promise( (resolve, reject) => {
            if(typeof encryptedKeys == "string") {
                encryptedKeys = Buffer.from(encryptedKeys, 'hex');
            }
            const iv=Buffer.from(encryptedKeys.toString('hex').substring(0,32), 'hex');
            const encrypted=Buffer.from(encryptedKeys.toString('hex').substring(32), 'hex');
            const decipher = crypto.createDecipheriv('aes-256-cbc', crypto.createHash('sha256').update(keyFilePassphrase, 'binary').digest(), iv);
            let decrypted = decipher.update(encrypted);
            decrypted = Buffer.concat([decrypted, decipher.final()]);
            const keys = JSON.parse(decrypted.toString());
            resolve( keys );
        });
    }

    /**
     * saveKeys
     * 
     * This method saves the given keys to the given filename, encrypting them
     * for security (using encryptKeys above) using the given password.
     * 
     * On success, the promise is resolved with the filename.
     * 
     * @param {object} keys 
     * @param {string} keyFilePassphrase
     * @param {string} keyFileName 
     * @returns {Promise}
     */
    static saveKeys(keys, keyFilePassphrase, keyFileName) {
        return new Promise( (resolve, reject) => {
            CryptClient.encryptKeys(keys, keyFilePassphrase).then(encrypted => {
                fs.writeFile(keyFileName, Buffer.from(encrypted, 'hex'), err => {
                    if(err) {
                        reject(err);
                    } else {
                        resolve( keyFileName );
                    }
                });
            }).catch( err => reject(err));
        });
    }

    /**
     * loadKeys
     * 
     * This method loads a given file, decrypts it and returns the keys. This is the
     * inverse of saveKeys above.
     * 
     * On success, the promise is resolved with the keys object
     * 
     * @param {*} keyFileName 
     * @param {*} keyFilePassphrase 
     * @returns {Promise}
     */
    static loadKeys(keyFileName, keyFilePassphrase) {
        return new Promise( (resolve, reject) => {
            fs.readFile(keyFileName, (err, data) => {
                if(err) {
                    reject(err);
                } else {
                    CryptClient.decryptKeys(data, keyFilePassphrase).then(keys => {
                        resolve( keys );
                    }).catch( err => reject(err));
                }
            });
        });
    }

    /**
     * setKeyFile
     * 
     * This method is used internally to save the current set of keys. This is a
     * wrapper around saveKeys above to use the instance's stored keyset and filename;
     * in normal usage you will not need to call this manually as this is called during
     * init.
     * 
     * @param {string} keyFilePassphrase 
     * @returns {Promise}
     */
    setKeyFile(keyFilePassphrase) {
        return new Promise( (resolve, reject) => {
            CryptClient.saveKeys(this.keys, keyFilePassphrase, this.keyFileName)
                .then( filename => resolve(filename) )
                .catch( err => reject(err) );
        });
    }

    /**
     * getKeyFile
     * 
     * This method is used internally to read the current set of keys. This is a wrapper
     * around loadKeys above to use the instance's stored keyfile; in normal usage you will
     * not need to call this manually as this is called during init.
     * 
     * @param {string} keyFilePassphrase 
     * @returns {Promise}
     */
    getKeyFile(keyFilePassphrase) {
        return new Promise( (resolve, reject) => {
            CryptClient.loadKeys(this.keyFileName, keyFilePassphrase)
                .then( keys => {
                    this.keys = keys;
                    resolve(keys);
                })
                .catch( err => reject(err) );
        });
    }

    /**
     * getPublicKey
     * 
     * Returns the public key which can be used to encrypt data
     * @returns {string}
     */
    getPublicKey() {
        return this.keys.publicKey;
    }

    encrypt(data) {
        return new Promise( (resolve,reject) => {
            const iv = crypto.randomBytes(16);
            const key = crypto.randomBytes(64);
            const cipher = crypto.createCipheriv('aes-256-cbc', crypto.createHash('sha256').update(key, 'binary').digest(), iv );
            let encrypted = '';
            cipher.on('readable', () => {
                let chunk;
                while (null !== (chunk = cipher.read())) { 
                    encrypted += chunk.toString('hex'); 
                } 
            });
            cipher.on('end',() => {
                const encryptedData = iv.toString('hex') + encrypted;
                const encryptedDataKey = crypto.publicEncrypt(this.keys.publicKey,key);
                resolve( [encryptedDataKey, encryptedData] );
            });
            cipher.write(data);
            cipher.end();
        });
    }

    decrypt(encryptedDataKey, encryptedData, privateKeyPassphrase) {
        return new Promise( (resolve,reject) => {
            const fn = passphrase => {
                const key=crypto.privateDecrypt({
                    key: this.keys.privateKey,
                    passphrase: this.keys.passphrase ? Buffer.from(this.keys.passphrase, 'hex') : passphrase
                }, encryptedDataKey);
                const iv=Buffer.from(encryptedData.toString('hex').substring(0,32), 'hex');
                const encrypted=Buffer.from(encryptedData.toString('hex').substring(32), 'hex');
                const decipher = crypto.createDecipheriv('aes-256-cbc', crypto.createHash('sha256').update(key, 'binary').digest(), iv);
                let decrypted = decipher.update(encrypted);
                decrypted = Buffer.concat([decrypted, decipher.final()]);
                resolve(decrypted);   
            };
            if( typeof privateKeyPassphrase == "function" && !this.keys.passphrase) {
                privateKeyPassphrase().then(passphrase => {
                    fn(passphrase);
                }).catch(err => reject(err));
            } else {
                fn(privateKeyPassphrase);
            }

        });
    }
}
