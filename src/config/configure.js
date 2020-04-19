'use strict';
const util = require('../util');

export class ConfigHelper {
  constructor(data, defaults) {
    this.config = data || {};
    this.defaults = defaults || {};
  }

  /**
   * @param {string} key
   */
  getItem(key) {
    let result = util.getObjectRef(this.config, key);
    if (typeof result === 'undefined' || result === null) {
      result = util.getObjectRef(this.defaults, key);
    }
    return result;
  }

  /**
   * @param {string} key
   * @param {any} value
   */
  setItem(key, value) {
    return util.setObjectRef(this.config, key, value);
  }

  /** @param {string} key */
  removeItem(key) {
    return util.delObjectRef(this.config, key);
  }
}
