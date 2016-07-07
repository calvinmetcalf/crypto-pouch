'use strict';
var encrypt = require('native-crypto/encrypt');
var decrypt = require('native-crypto/decrypt');
exports.encrypt = function encryptChacha(data, key, nonce, aad) {
  return encrypt(key, nonce, data, aad).then(function (resp) {
    return {
      tag: resp.slice(-16).toString('hex'),
      data: resp.slice(0, -16).toString('hex')
    }
  });
};
exports.decrypt = function decryptChacha(data, key, nonce, aad, tag) {
  var encryptedData =  Buffer.concat([data, tag]);
  return decrypt(key, nonce, encryptedData, aad).then(function (resp) {
    return resp.toString();
  });
};
