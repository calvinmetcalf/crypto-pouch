'use strict';
var pbkdf2 = require('native-crypto/pbkdf2');
var randomBytes = require('randombytes');
var configId = '_local/crypto';
var chachaHelper = require('./chacha');
var gcmHelper = require('./gcm');
var defaultDigest = 'sha256';
var defaultIterations = 100000;
var previousIterations = 1000;
var defaultAlgo = 'aes-gcm';
var transform = require('transform-pouch').transform;
var uuid = require('uuid');
function noop(){}
function cryptoInit(password, options) {
  var db = this;
  var key, cb;
  var turnedOff = false;
  var ignore = ['_id', '_rev', '_deleted']
  if (!options) {
    options = {};
  }
  var algo;
  if (password && typeof password === 'object') {
    options = password;
    password = password.password;
    delete options.password;
  }
  if (options.ignore) {
    ignore = ignore.concat(options.ignore);
  }
  if(typeof options.cb === 'function') {
    cb = options.cb;
  } else {
    cb = noop;
  }
  var pending;
  if (options.key && !Buffer.isBuffer(options.key) && options.key instanceof global.Uint8Array) {
    options.key = new Buffer(options.key)
  }
  if (Buffer.isBuffer(options.key) && options.key.length === 32) {
    key = options.key;
    pending = db.get(configId).catch(function () {
      return {};
    }).then(function (doc) {
      algo = setAlgo(doc);
    });
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
          iterations: iterations,
          algo: options.algorithm || defaultAlgo
        };
      } else if (err.status === 'invalid' && err.doc) {
        doc = err.doc;
        doc.salt = randomBytes(16).toString('hex');
        doc.digest = digest;
        doc.iterations = iterations;
        doc.algo = options.algorithm || defaultAlgo;
      }
      if (doc) {
        return db.put(doc).then(function () {
          return doc;
        });
      }
      throw err;
    }).then(function (doc) {
      algo = setAlgo(doc);
      return pbkdf2(password, new Buffer(doc.salt, 'hex'), doc.iterations || options.iteration || previousIterations, 256 / 8, doc.digest || digest);
    }).then(function (_key) {
      password = null;
      if (turnedOff) {
        randomize(key);
      } else {
        key = _key;
      }
      process.nextTick(function () {
        cb(null, key);
      });
    }).catch(function (e) {
      process.nextTick(function (){
        cb(e);
      });
      throw e;
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
  function setAlgo(doc) {
    if (typeof doc.algo !== 'string') {
      return chachaHelper;
    } else if (doc.algo.toLowerCase().indexOf('chacha') > -1) {
      return chachaHelper;
    } else if (doc.algo.toLowerCase().indexOf('gcm') > -1) {
      return gcmHelper;
    } else {
      throw new Error('invalid algo');
    }
  }
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
    return algo.encrypt(data, key, nonce, new Buffer(outDoc._id)).then(function (resp) {
      outDoc.tag = resp.tag;
      outDoc.data = resp.data;
      return outDoc;
    })
  }
  function decrypt(doc) {
    if (turnedOff || !doc.nonce || !doc._id || !doc.tag || !doc.data) {
      return doc;
    }
    return algo.decrypt(new Buffer(doc.data, 'hex'), key, new Buffer(doc.nonce, 'hex'), new Buffer(doc._id), new Buffer(doc.tag, 'hex')).then(function (outData) {
      var out = JSON.parse(outData);
      for (var i = 0, len = ignore.length; i < len; i++) {
        out[ignore[i]] = doc[ignore[i]]
      }
      return out;
    });
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
