'use strict';
var pbkdf2 = require('pbkdf2');
var randomBytes = require('randombytes');
var chacha = require('chacha');
var PouchPromise = require('pouchdb-promise');
var configId = '_local/crypto';
var transform = require('transform-pouch').transform;
var uuid = require('node-uuid');
function genKey(password, salt) {
  return new PouchPromise(function (resolve, reject) {
    pbkdf2.pbkdf2(password, salt, 1000, 256 / 8, function (err, key) {
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
  var key, pub;
  var turnedOff = false;
  var pending = db.get(configId).then(function (doc){
    if (!doc.salt) {
      throw {
        status: 'invalid',
        doc: doc
      };
    }
    return doc;
  }).catch(function (err) {
    var doc;
    if (err.status === 404) {
      doc = {
        _id: configId,
        salt: randomBytes(16).toString('hex')
      };
    } else if (err.status === 'invalid' && err.doc) {
      doc = err.doc;
      doc.salt = randomBytes(16).toString('hex');
    }
    if (doc) {
      return db.put(doc).then(function () {
        return doc;
      });
    }
    throw err;
  }).then(function (doc) {
    return genKey(password, new Buffer(doc.salt, 'hex'));
  }).then(function (_key) {
    password = null;
    if (turnedOff) {
      randomize(key);
    } else {
      key = _key;
    }
  });
  db.transform({
    incoming: function (doc) {
      return pending.then(function () {
        return encrypt(doc);
      });
    },
    outgoing: function (doc) {
      return pending.then(function () {
        return decrypt(doc);
      });
    }
  });
  db.removeCrypto = function () {
    if (key) {
      randomize(key);
    }
    turnedOff = true;
  };
  return pending;
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
    var data = JSON.stringify(doc);
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
    if (turnedOff || !doc.nonce || !doc._id || !doc.tag || !doc.data) {
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
  var len = buf.length;
  var data = randomBytes(len);
  var i = -1;
  while (++i < len) {
    buf[i] = data[i];
  }
}

exports.transform = transform;
exports.crypto = cryptoInit;

if (typeof window !== 'undefined' && window.PouchDB) {
  window.PouchDB.plugin(module.exports);
}
