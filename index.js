'use strict';
var crypto = require('crypto');
var chacha = require('chacha');
var PouchPromise = require('pouchdb-promise');
var configId = '_local/crypto';
var transform = require('transform-pouch').transform;
var uuid = require('node-uuid');
function genKey(password, salt) {
  return new PouchPromise(function (resolve, reject) {
    crypto.pbkdf2(password, salt, 1000, 256 / 8, function (err, key) {
      password = null;
      if (err) {
        return reject(err);
      }
      resolve(key);
    });
  });
}
function cryptoInit(password, options) {
  var db = this;
  var key, pub;
  var turnedOff = false;
  var ignore = ['_id', '_rev']
  var modP

  if (typeof options === 'string' || Buffer.isBuffer(options)) {
    modP = options
  }
  if (options && options.ignore) {
    ignore = ignore.concat(options.ignore)
  }
  if (options && options.modP) {
    modP = options.modP
  }
  return db.get(configId).catch(function (err) {
    if (err.status === 404) {
      var doc = {
        _id: configId,
        salt: crypto.randomBytes(16).toString('hex')
      };
      return db.put(doc).then(function () {
        return doc;
      });
    }
    throw err;
  }).then(function (doc) {
    var dh;
    if (typeof modP === 'string') {
      dh = crypto.getDiffieHellman(modP);
      dh.generateKeys();
      pub = dh.getPublicKey();
      password = dh.computeSecret(password);
    } else if (Buffer.isBuffer(modP)) {
      dh = crypto.createDiffieHellman(modP);
      dh.generateKeys();
      pub = dh.getPublicKey();
      password = dh.computeSecret(password);
    }
    return genKey(password, new Buffer(doc.salt, 'hex'));
  }).then(function (_key) {
    password = null;
    key = _key;
    db.transform({
      incoming: encrypt,
      outgoing: decrypt
    });
    db.removeCrypto = function () {
      randomize(key);
      turnedOff = true;
    };
    if (pub) {
      return pub;
    }
  });
  function encrypt(doc) {
    if (turnedOff) {
      return doc;
    }
    var nonce = crypto.randomBytes(12);
    var outDoc = {
      nonce: nonce.toString('hex')
    }
    // for loop performs better than .forEach etc
    for (var i = 0, len = ignore.length; i < len; i++) {
      outDoc[ignore[i]] = doc[ignore[i]]
      delete doc[ignore[i]]
    }
    if (!outDoc._id) {
      outDoc._id = uuid.v4()
    }

    // Encrypting attachments is complicated
    // https://github.com/calvinmetcalf/crypto-pouch/pull/18#issuecomment-186402231
    if (doc._attachments) {
      throw new Error('Attachments cannot be encrypted. Use {ignore: "_attachments"} option')
    }

    var data = JSON.stringify(doc);
    var cipher = chacha.createCipher(key, nonce);
    cipher.setAAD(new Buffer(outDoc._id));
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
    for (var i = 0, len = ignore.length; i < len; i++) {
      out[ignore[i]] = doc[ignore[i]]
    }
    return out;
  }
}
function randomize(buf) {
  var len = buf.length;
  var data = crypto.randomBytes(len);
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
