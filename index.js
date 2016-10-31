'use strict';
var crypto = require('crypto');
var PouchPromise = require('pouchdb-promise');
var configId = '_local/crypto2';
var defaultDigest = 'sha512';
var defaultAlgorithm = 'aes-256-gcm';
var transform = require('transform-pouch').transform;
var uuid = require('node-uuid');
function genKey(password, salt, digest) {
  return new PouchPromise(function (resolve, reject) {
    crypto.pbkdf2(password, salt, 1000, 256 / 8, digest, function (err, key) {
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
  var key, algorithm;
  var turnedOff = false;
  var ignore = ['_id', '_rev', '_deleted'];

  if (!options) {
    options = {};
  }
  if (options.ignore) {
    ignore = ignore.concat(options.ignore);
  }
  if (!options.digest) {
    options.digest = defaultDigest;
  }
  if (!options.algorithm) {
    options.algorithm = defaultAlgorithm;
  }

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
        algorithm: options.algorithm,
        digest: options.digest,
        salt: crypto.randomBytes(16).toString('hex')
      };
    } else if (err.status === 'invalid' && err.doc) {
      doc = err.doc;
      doc.salt = crypto.randomBytes(16).toString('hex');
    }
    if (doc) {
      return db.put(doc).then(function () {
        return doc;
      });
    }
    throw err;
  }).then(function (doc) {
    algorithm = doc.algorithm;
    return genKey(password, new Buffer(doc.salt, 'hex'), doc.digest);
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

  function encrypt(doc) {
    var nonce = crypto.randomBytes(12)
    var outDoc = {
      nonce: nonce.toString('hex')
    };
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
    var cipher = crypto.createCipheriv(algorithm, key, nonce);
    cipher.setAAD(new Buffer(outDoc._id));
    outDoc.data = cipher.update(data, 'utf8', 'hex');
    outDoc.data += cipher.final('hex');
    outDoc.tag = cipher.getAuthTag().toString('hex');
    return outDoc;
  }
  function decrypt(doc) {
    if (turnedOff || !doc.nonce || !doc._id || !doc.tag || !doc.data) {
      return doc;
    }
    var decipher = crypto.createDecipheriv(algorithm, key, new Buffer(doc.nonce, 'hex'));
    decipher.setAAD(new Buffer(doc._id));
    decipher.setAuthTag(new Buffer(doc.tag, 'hex'));
    var out = decipher.update(doc.data, 'hex', 'utf8');
    out += decipher.final('utf8');
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
