'use strict';
var chacha = require('chacha');
var PouchPromise = require('pouchdb-promise');

exports.encrypt = function encryptChacha(data, key, nonce, aad) {
  return new PouchPromise(function (yes) {
    var outDoc = {};
    var cipher = chacha.createCipher(key, nonce);
    cipher.setAAD(aad);
    outDoc.data = cipher.update(data).toString('hex');
    cipher.final();
    outDoc.tag = cipher.getAuthTag().toString('hex');
    yes(outDoc);
  });
};
exports.decrypt = function decryptChacha(data, key, nonce, aad, tag) {
  return new PouchPromise(function (yes) {
    var decipher = chacha.createDecipher(key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    var out = decipher.update(data).toString();
    decipher.final();
    yes(out);
  });
};
