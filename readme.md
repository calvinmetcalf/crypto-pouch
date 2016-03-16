crypto pouch [![Build Status](https://travis-ci.org/calvinmetcalf/crypto-pouch.svg)](https://travis-ci.org/calvinmetcalf/crypto-pouch)
===

Plugin to encrypt a PouchDB/CouchDB database.

```js
var db = new PouchDB('my_db');

db.crypto(password).then(function (publicKey) {
  // all done, docs should be transparently encrypted/decrypted
});

db.removeCrypto(); // will no longer encrypt decrypt your data
```

It currently encrypts with the [Chacha20-Poly1305](https://github.com/calvinmetcalf/chacha20poly1305) algorithm, but this may be changed 
to AES256-GCM when Node 0.12.0 drops.

**Note**: Due to performance reasons this module does not encrypt attachments ([#18](https://github.com/calvinmetcalf/crypto-pouch/pull/18))

Usage
-------

This plugin is hosted on npm. To use in Node.js:

```bash
npm install crypto-pouch
```

If you want to use it in the browser, download [the browserified version from wzrd.in](http://wzrd.in/bundle/crypto-pouch) and then include it after `pouchdb`:

```html
<script src="pouchdb.js"></script>
<script src="pouchdb.crypto-pouch.js"></script>
```

API
--------


### db.crypto(password [, diffieHellman])

Set up encryption on the database. Returns a promise.

If the second argument is a string, it is taken to be a Diffie-Hellman ModP group and if a buffer then a prime 
and the password is interpreted as a Diffie-Hellman public key. If so, the public key 
for use with the database is returned; you can use that to calculate the shared secret 
which is needed for subsequently opening the data set.


### db.removeCrypto()

Disables encryption on the database.

Details
===

If you replicate to another database, it will decrypt before sending it to 
the external one. So make sure that one also has a password set as well if you want 
it encrypted too.

If you change the name of a document, it will throw an error when you try 
to decrypt it. If you manually move a document from one database to another, 
it will not decrypt correctly.  If you need to decrypt it a file manually 
you will find a local doc named `_local/crypto` in the database. This doc has a field 
named `salt` which is a hex-encoded buffer. Run on your password with that as salt 
for 1000 iterations to generate a 32 byte (256 bit) key; that is the key 
for decoding documents.

Each document has 3 relevant fields: `data`, `nonce`, and `tag`. 
`nonce` is the initialization vector to give to chacha20 in addition to the key 
you generated. Pass the document `_id` as additional authenticated data and the tag 
as the auth tag and then decrypt the data.  If it throws an error, then you either 
screwed up or somebody modified the data.

Examples
===

Derive key from password and salt
---

```js
db.get('_local/crypto').then(function (doc) {
  return new Promise(function (resolve, reject) {
    crypto.pbkdf2(password, doc.salt, 1000, 256/8, function (err, key) {
      if (err) {
        return reject(err);
      }
      resolve(key);
    });
  });
}).then(function (key) {
  // you have the key
});
```

Decrypt a document
---

```js
var chacha = require('chacha');

db.get(id).then(function (doc) {
   var decipher = chacha.createDecipher(key, new Buffer(doc.nonce, 'hex'));
  decipher.setAAD(new Buffer(doc._id));
  decipher.setAuthTag(new Buffer(doc.tag, 'hex'));
  var out = decipher.update(new Buffer(doc.data, 'hex')).toString();
  decipher.final();
  // parse it AFTER calling final
  // you don't want to parse it if it has been manipulated
  out = JSON.parse(out);
  out._id = doc._id;
  out._rev = doc._rev;
  return out;
});
```
