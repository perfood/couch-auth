'use strict';
import { delObjectRef, getObjectRef, setObjectRef } from '../util';
import { Config } from '../types/config';

export class ConfigHelper {
  config: Partial<Config>;
  defaults: Partial<Config>;

  constructor(data: Partial<Config> = {}, defaults: Partial<Config> = {}) {
    this.config = data;
    this.defaults = defaults;
  }

  /** Verifies the config against some incompatible settings */
  verifyConfig() {
    if (this.config.dbServer?.cloudant && this.getItem('session.dbFallback')) {
      throw 'dbFallback is only implemented for CouchDB.';
    }
    if (
      this.config.dbServer?.iamApiKey &&
      (this.config.dbServer?.password || process.env.CLOUDANT_PASS)
    ) {
      throw 'do not provide a password when using IAM authentication!';
    }
  }

  getItem(key: string) {
    let result = getObjectRef(this.config, key);
    if (typeof result === 'undefined' || result === null) {
      result = getObjectRef(this.defaults, key);
    }
    return result;
  }

  setItem(key: string, value: any) {
    return setObjectRef(this.config, key, value);
  }

  /** @param {string} key */
  removeItem(key: string) {
    return delObjectRef(this.config, key);
  }
}
