'use strict';
const util = require('./util');
const extend = require('util')._extend;
const RedisAdapter = require('./sessionAdapters/RedisAdapter');
const MemoryAdapter = require('./sessionAdapters/MemoryAdapter');
const FileAdapter = require('./sessionAdapters/FileAdapter');

const tokenPrefix = 'token';

class Session {
  #adapter;
  #dbAuth;
  invalidMsg = 'invalid token';
  constructor(config) {
    let adapter;
    const sessionAdapter = config.getItem('session.adapter');
    if (sessionAdapter === 'redis') {
      adapter = new RedisAdapter(config);
    } else if (sessionAdapter === 'file') {
      adapter = new FileAdapter(config);
    } else {
      adapter = new MemoryAdapter();
    }
    this.#adapter = adapter;
  }
  storeToken(token) {
    token = extend({}, token);
    if (!token.password && token.salt && token.derived_key) {
      return this.#adapter
        .storeKey(
          tokenPrefix + ':' + token.key,
          token.expires - Date.now(),
          JSON.stringify(token)
        )
        .then(() => {
          delete token.salt;
          delete token.derived_key;
          return Promise.resolve(token);
        });
    }
    return util
      .hashPassword(token.password)
      .then(hash => {
        token.salt = hash.salt;
        token.derived_key = hash.derived_key;
        delete token.password;
        return this.#adapter.storeKey(
          tokenPrefix + ':' + token.key,
          token.expires - Date.now(),
          JSON.stringify(token)
        );
      })
      .then(() => {
        delete token.salt;
        delete token.derived_key;
        return Promise.resolve(token);
      });
  }

  deleteTokens(keys) {
    var entries = [];
    if (!(keys instanceof Array)) {
      keys = [keys];
    }
    keys.forEach(function (key) {
      entries.push(tokenPrefix + ':' + key);
    });
    return this.#adapter.deleteKeys(entries);
  }

  async confirmToken(key, password) {
    try {
      const result = await this.#adapter.getKey(tokenPrefix + ':' + key);
      if (!result) {
        throw this.invalidMsg;
      }
      let token = JSON.parse(result);
      await util.verifyPassword(token, password);
      delete token.salt;
      delete token.derived_key;
      return token;
    } catch (error) {
      throw this.invalidMsg;
    }
  }
  /**
   * retrieved the key from the session adapter
   * @param {string} key
   */
  fetchToken(key) {
    return this.#adapter.getKey(tokenPrefix + ':' + key).then(result => {
      return Promise.resolve(JSON.parse(result));
    });
  }
  quit() {
    return this.#adapter.quit();
  }
}

module.exports = Session;
