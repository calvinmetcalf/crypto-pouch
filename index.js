'use strict';
var randomBytes = require('randombytes');
var chacha = require('chacha');
var PouchPromise = require('pouchdb-promise');
var configId = '_local/crypto';
var transform = require('transform-pouch').transform;
var pubEnc = require('public-encrypt');
var uuid = require('node-uuid');
var pbkdf2 = require('pbkdf2').pbkdf2;
function genKey(password, salt) {
  return new PouchPromise(function (resolve, reject) {
    pbkdf2(password, salt, 1000, 32, 'sha512', function (err, key) {
      password = null;
      if (err) {
        return reject(err);
      }
      resolve(key);
    });
  });
}
function cryptoInit(password) {
  var db = this;
  var key;
  var turnedOff = false;
  return db.get(configId).catch(function (err) {
    if (err.status === 404) {

      var doc;
      if (typeof password !== 'string') {
        doc = {
          _id: configId,
          key: pubEnc.publicEncrypt(password, randomBytes(32)).toString('hex')
        };
        key = doc.key;
      } else {
        doc = {
          _id: configId,
          salt: randomBytes(32).toString('hex')
        };
      }
      return db.put(doc).then(function () {
        return doc;
      });
    }
    throw err;
  }).then(function (doc) {
    if (typeof password !== 'string') {
      if (key) {
        randomize(password);
        return key;
      }
      var _key = pubEnc.privateDecrypt(password, new Buffer(doc.key, 'hex'));
      randomize(password);
      return _key;
    }
    return genKey(password, new Buffer(doc.salt, 'hex'));
  }).then(function (_key) {
    password = null;
    key = _key;
    transform.call(db, {
      incoming: encrypt,
      outgoing: decrypt
    });
    db.removeCrypto = function () {
      randomize(key);
      turnedOff = true;
    };
  });
  function encrypt(doc) {
    if (turnedOff) {
      return doc;
    }
    var id, rev;
    if ('_id' in doc) {
      id = doc._id;
      delete doc._id;
    } else {
      id = uuid.v4();
    }
    if ('_rev' in doc) {
      rev = doc._rev;
      delete doc._rev;
    }
    var nonce = randomBytes(12);
    var data = new Buffer(JSON.stringify(doc));
    var outDoc = {
      _id: id,
      nonce: nonce.toString('hex')
    };
    if (rev) {
      outDoc._rev = rev;
    }
    var cipher = chacha.createCipher(key, nonce);
    cipher.setAAD(new Buffer(id));
    outDoc.data = cipher.update(data).toString('hex');
    cipher.final();
    outDoc.tag = cipher.getAuthTag().toString('hex');
    return outDoc;
  }
  function decrypt(doc) {
    if (turnedOff) {
      return doc;
    }
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
  }
}

function randomize(buf) {
  if (buf.key) {
    buf = buf.key;
  }
  var len = buf.length;
  var data = randomBytes(len);
  var i = -1;
  while (++i < len) {
    buf[i] = data[i];
  }
}

if (typeof window !== 'undefined' && window.PouchDB) {
  window.PouchDB.plugin(module.exports);
}
exports.crypto = cryptoInit;
