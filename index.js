'use strict';
var pbkdf2 = require('pbkdf2');
var randomBytes = require('randombytes');
var chacha = require('chacha');
var PouchPromise = require('pouchdb-promise');
var configId = '_local/crypto';
var defaultDigest = 'sha256';
var defaultIterations = 100000;
var previousIterations = 1000;
var transform = require('transform-pouch').transform;
var uuid = require('node-uuid');
function genKey(password, salt, digest, iterations) {
  return new PouchPromise(function (resolve, reject) {
    pbkdf2.pbkdf2(password, salt, iterations, 256 / 8, digest, function (err, key) {
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
  var ignore = ['_id', '_rev', '_deleted']
  if (!options) {
    options = {};
  }
  if (password && typeof password === 'object') {
    options = password;
    password = password.password;
    delete options.password;
  }
  if (options.ignore) {
    ignore = ignore.concat(options.ignore);
  }
  var pending;
  if (Buffer.isBuffer(options.key) && options.key.length === 32) {
    key = options.key;
    pending = Promise.resolve();
  } else {
    var digest = options.digest || defaultDigest;
    var iterations = options.iteration || defaultIterations;
    pending = db.get(configId).then(function (doc){
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
          salt: randomBytes(16).toString('hex'),
          digest: digest,
          iterations: iterations
        };
      } else if (err.status === 'invalid' && err.doc) {
        doc = err.doc;
        doc.salt = randomBytes(16).toString('hex');
        doc.digest = digest;
        doc.iterations = iterations;
      }
      if (doc) {
        return db.put(doc).then(function () {
          return doc;
        });
      }
      throw err;
    }).then(function (doc) {
      return genKey(password, new Buffer(doc.salt, 'hex'), doc.digest || digest, doc.iterations || options.iteration || previousIterations);
    }).then(function (_key) {
      password = null;
      if (turnedOff) {
        randomize(key);
      } else {
        key = _key;
      }
    });
  }
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
    var nonce = randomBytes(12)
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
