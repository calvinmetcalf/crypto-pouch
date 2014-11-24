var crypto = require('crypto');
var chacha = require('chacha');
var Promise = require('pouchdb-promise');
var configId = '_local/crypto';
function genKey(password, salt) {
  return new Promise(function (resolve, reject) {
    crypto.pbkdf2(password, salt, 1000, 256/8, function (err, key) {
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
  
  return db.get(configId).catch(function (err) {
    if (err.status === 404) {
      var doc = {
        _id: configId,
        salt: crypto.randomBytes(16)
      };
      return db.put(doc).then(function () {
        return doc;
      });
    }
    throw err;
  }).then(function (doc) {
    return genKey(password, doc.salt);
  }).then(function (_key) {
    key = _key;
    db.putCrypto = put;
    db.getCrypto = get;
    return {ok: true};
  });
  function put(doc, id, rev) {
    if ('_id' in doc) {
      id = doc._id;
      delete doc._id;
    }
    if ('_rev' in doc) {
      rev = doc._rev;
      delete doc._rev;
    }
    var nonce = crypto.randomBytes(12);
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
    outDoc.data = cipher.update(data);
    cipher.finish();
    outDoc.tag = cipher.getAuthTag().toString('hex');
    return db.put(outDoc);
  }
  function get(id, rev) {
    return db.get(id).then(function (doc) {
      var decipher = chacha.createDecipher(key, doc.nonce);
      decipher.setAAD(new Buffer(id));
      decipher.setAuthTag(new Buffer(doc.tag, 'hex'));
      var out = decipher.update(doc.data);
      decipher.finish();
      return out;
    });
  }
}
exports.crypto = cryptoInit;