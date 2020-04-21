"use strict";
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, privateMap, value) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to set private field on non-instance");
    }
    privateMap.set(receiver, value);
    return value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, privateMap) {
    if (!privateMap.has(receiver)) {
        throw new TypeError("attempted to get private field on non-instance");
    }
    return privateMap.get(receiver);
};
var _keys, _expires;
Object.defineProperty(exports, "__esModule", { value: true });
class MemoryAdapter {
    constructor(config) {
        _keys.set(this, void 0);
        _expires.set(this, void 0);
        __classPrivateFieldSet(this, _keys, {});
        __classPrivateFieldSet(this, _expires, {});
        console.log('Memory Adapter loaded');
    }
    storeKey(key, life, data) {
        const now = Date.now();
        __classPrivateFieldGet(this, _keys)[key] = data;
        __classPrivateFieldGet(this, _expires)[key] = now + life;
        this.removeExpired();
        return Promise.resolve();
    }
    getKey(key) {
        const now = Date.now();
        if (__classPrivateFieldGet(this, _keys)[key] && __classPrivateFieldGet(this, _expires)[key] > now) {
            return Promise.resolve(__classPrivateFieldGet(this, _keys)[key]);
        }
        else {
            return Promise.resolve(false);
        }
    }
    deleteKeys(keys) {
        if (!(keys instanceof Array)) {
            keys = [keys];
        }
        keys.forEach(key => {
            delete __classPrivateFieldGet(this, _keys)[key];
            delete __classPrivateFieldGet(this, _expires)[key];
        });
        this.removeExpired();
        return Promise.resolve(keys.length);
    }
    quit() {
        return Promise.resolve();
    }
    removeExpired() {
        const now = Date.now();
        Object.keys(__classPrivateFieldGet(this, _expires)).forEach(key => {
            if (__classPrivateFieldGet(this, _expires)[key] < now) {
                delete __classPrivateFieldGet(this, _keys)[key];
                delete __classPrivateFieldGet(this, _expires)[key];
            }
        });
    }
}
exports.MemoryAdapter = MemoryAdapter;
_keys = new WeakMap(), _expires = new WeakMap();
