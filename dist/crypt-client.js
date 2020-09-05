"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _crypto = _interopRequireWildcard(require("crypto"));

var _fs = _interopRequireDefault(require("fs"));

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _getRequireWildcardCache() { if (typeof WeakMap !== "function") return null; var cache = new WeakMap(); _getRequireWildcardCache = function () { return cache; }; return cache; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

class CryptClient {
  constructor(keyFileName) {
    this.keyFileName = keyFileName;
  }

  static init(keyFile, keyFilePassphrase, privateKeyPassphrase = null) {
    return new Promise((resolve, reject) => {
      const instance = new CryptClient(keyFile);

      _fs.default.access(keyFile, err => {
        if (err) {
          const fn = passphrase => {
            CryptClient.generateKeys(passphrase).then(keys => {
              instance.keys = keys;
              instance.setKeyFile(keyFilePassphrase).then(() => resolve(instance)).catch(err => reject(err));
            }).catch(err => reject(err));
          };

          if (typeof privateKeyPassphrase == "function") {
            privateKeyPassphrase().then(passphrase => {
              fn(passphrase);
            }).catch(err => reject(err));
          } else {
            fn(privateKeyPassphrase);
          }
        } else {
          instance.getKeyFile(keyFilePassphrase).then(keyFile => resolve(instance)).catch(err => reject(err));
        }
      });
    });
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
   * @returns Promise
   */


  static generateKeys(privateKeyPassphrase) {
    return new Promise((resolve, reject) => {
      const passphrase = privateKeyPassphrase !== null && privateKeyPassphrase !== void 0 ? privateKeyPassphrase : _crypto.default.randomBytes(32);
      const keys = {};

      _crypto.default.generateKeyPair('rsa', {
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
        if (err) {
          reject(err);
        } else {
          keys.publicKey = publicKey;
          keys.privateKey = privateKey;

          if (!privateKeyPassphrase) {
            keys.passphrase = passphrase.toString("hex");
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
   * @returns Promise
   */


  static encryptKeys(keys, keyFilePassphrase) {
    return new Promise((resolve, reject) => {
      const iv = _crypto.default.randomBytes(16);

      const cipher = _crypto.default.createCipheriv('aes-256-cbc', _crypto.default.createHash('sha256').update(keyFilePassphrase, 'binary').digest(), iv);

      let encrypted = '';
      cipher.on('readable', () => {
        let chunk;

        while (null !== (chunk = cipher.read())) {
          encrypted += chunk.toString('hex');
        }
      });
      cipher.on('end', () => {
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
   */


  static decryptKeys(encryptedKeys, keyFilePassphrase) {
    return new Promise((resolve, reject) => {
      if (typeof encryptedKeys == "string") {
        encryptedKeys = Buffer.from(encryptedKeys, 'hex');
      }

      const iv = Buffer.from(encryptedKeys.toString('hex').substring(0, 32), 'hex');
      const encrypted = Buffer.from(encryptedKeys.toString('hex').substring(32), 'hex');

      const decipher = _crypto.default.createDecipheriv('aes-256-cbc', _crypto.default.createHash('sha256').update(keyFilePassphrase, 'binary').digest(), iv);

      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      const keys = JSON.parse(decrypted.toString());
      resolve(keys);
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
   * @returns Promise
   */


  static saveKeys(keys, keyFilePassphrase, keyFileName) {
    return new Promise((resolve, reject) => {
      CryptClient.encryptKeys(keys, keyFilePassphrase).then(encrypted => {
        _fs.default.writeFile(keyFileName, Buffer.from(encrypted, 'hex'), err => {
          if (err) {
            reject(err);
          } else {
            resolve(keyFileName);
          }
        });
      });
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
   * @returns Promise
   */


  static loadKeys(keyFileName, keyFilePassphrase) {
    return new Promise((resolve, reject) => {
      _fs.default.readFile(keyFileName, (err, data) => {
        if (err) {
          reject(err);
        } else {
          CryptClient.decryptKeys(data, keyFilePassphrase).then(keys => {
            resolve(keys);
          }).catch(err => reject(err));
        }
      });
    });
  }

  setKeyFile(keyFilePassphrase) {
    return new Promise((resolve, reject) => {
      CryptClient.saveKeys(this.keys, keyFilePassphrase, this.keyFileName).then(filename => resolve(filename)).catch(err => reject(err));
    });
  }

  getKeyFile(keyFilePassphrase) {
    return new Promise((resolve, reject) => {
      CryptClient.loadKeys(this.keyFileName, keyFilePassphrase).then(keys => {
        this.keys = keys;
        resolve(keys);
      }).catch(err => reject(err));
    });
  }

  getPublicKey() {
    return this.keys.publicKey;
  }

  encrypt(data) {
    return new Promise((resolve, reject) => {
      const iv = _crypto.default.randomBytes(16);

      const key = _crypto.default.randomBytes(64);

      const cipher = _crypto.default.createCipheriv('aes-256-cbc', _crypto.default.createHash('sha256').update(key, 'binary').digest(), iv);

      let encrypted = '';
      cipher.on('readable', () => {
        let chunk;

        while (null !== (chunk = cipher.read())) {
          encrypted += chunk.toString('hex');
        }
      });
      cipher.on('end', () => {
        const encryptedData = iv.toString('hex') + encrypted;

        const encryptedDataKey = _crypto.default.publicEncrypt(this.keys.publicKey, key);

        resolve([encryptedDataKey, encryptedData]);
      });
      cipher.write(data);
      cipher.end();
    });
  }

  decrypt(encryptedDataKey, encryptedData, privateKeyPassphrase) {
    return new Promise((resolve, reject) => {
      const fn = passphrase => {
        const key = _crypto.default.privateDecrypt({
          key: this.keys.privateKey,
          passphrase: this.keys.passphrase ? Buffer.from(this.keys.passphrase, 'hex') : passphrase
        }, encryptedDataKey);

        const iv = Buffer.from(encryptedData.toString('hex').substring(0, 32), 'hex');
        const encrypted = Buffer.from(encryptedData.toString('hex').substring(32), 'hex');

        const decipher = _crypto.default.createDecipheriv('aes-256-cbc', _crypto.default.createHash('sha256').update(key, 'binary').digest(), iv);

        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        resolve(decrypted);
      };

      if (typeof privateKeyPassphrase == "function" && !this.keys.passphrase) {
        privateKeyPassphrase().then(passphrase => {
          fn(passphrase);
        }).catch(err => reject(err));
      } else {
        fn(privateKeyPassphrase);
      }
    });
  }

}

exports.default = CryptClient;