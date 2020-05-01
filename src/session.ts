'use strict';

import { hashPassword, verifyPassword } from './util';
import { FileAdapter } from './sessionAdapters/FileAdapter';
import { MemoryAdapter } from './sessionAdapters/MemoryAdapter';
import { RedisAdapter } from './sessionAdapters/RedisAdapter';

const extend = require('util')._extend;

const tokenPrefix = 'token';

export class Session {
  #adapter;
  static invalidMsg = 'invalid token';
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
    return hashPassword(token.password)
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
    const entries = [];
    if (!(keys instanceof Array)) {
      keys = [keys];
    }
    keys.forEach(key => {
      entries.push(tokenPrefix + ':' + key);
    });
    return this.#adapter.deleteKeys(entries);
  }

  async confirmToken(key: string, password: string) {
    try {
      const result = await this.#adapter.getKey(tokenPrefix + ':' + key);
      if (!result) {
        throw Session.invalidMsg;
      }
      const token = JSON.parse(result);
      await verifyPassword(token, password);
      delete token.salt;
      delete token.derived_key;
      return token;
    } catch (error) {
      throw Session.invalidMsg;
    }
  }
  /**
   * retrieved the key from the session adapter
   */
  fetchToken(key: string) {
    return this.#adapter.getKey(tokenPrefix + ':' + key).then(result => {
      return Promise.resolve(JSON.parse(result));
    });
  }
  quit() {
    return this.#adapter.quit();
  }
}
