'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const util_1 = require("../util");
class ConfigHelper {
    constructor(data = {}, defaults = {}) {
        this.config = data;
        this.defaults = defaults;
    }
    getItem(key) {
        let result = util_1.getObjectRef(this.config, key);
        if (typeof result === 'undefined' || result === null) {
            result = util_1.getObjectRef(this.defaults, key);
        }
        return result;
    }
    setItem(key, value) {
        return util_1.setObjectRef(this.config, key, value);
    }
    /** @param {string} key */
    removeItem(key) {
        return util_1.delObjectRef(this.config, key);
    }
}
exports.ConfigHelper = ConfigHelper;
