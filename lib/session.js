'use strict';
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
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
var _adapter;
Object.defineProperty(exports, "__esModule", { value: true });
const util_1 = require("./util");
const RedisAdapter_1 = require("./sessionAdapters/RedisAdapter");
const FileAdapter_1 = require("./sessionAdapters/FileAdapter");
const MemoryAdapter_1 = require("./sessionAdapters/MemoryAdapter");
const extend = require('util')._extend;
const tokenPrefix = 'token';
class Session {
    constructor(config) {
        _adapter.set(this, void 0);
        let adapter;
        const sessionAdapter = config.getItem('session.adapter');
        if (sessionAdapter === 'redis') {
            adapter = new RedisAdapter_1.RedisAdapter(config);
        }
        else if (sessionAdapter === 'file') {
            adapter = new FileAdapter_1.FileAdapter(config);
        }
        else {
            adapter = new MemoryAdapter_1.MemoryAdapter();
        }
        __classPrivateFieldSet(this, _adapter, adapter);
    }
    storeToken(token) {
        token = extend({}, token);
        if (!token.password && token.salt && token.derived_key) {
            return __classPrivateFieldGet(this, _adapter).storeKey(tokenPrefix + ':' + token.key, token.expires - Date.now(), JSON.stringify(token))
                .then(() => {
                delete token.salt;
                delete token.derived_key;
                return Promise.resolve(token);
            });
        }
        return util_1.hashPassword(token.password)
            .then(hash => {
            token.salt = hash.salt;
            token.derived_key = hash.derived_key;
            delete token.password;
            return __classPrivateFieldGet(this, _adapter).storeKey(tokenPrefix + ':' + token.key, token.expires - Date.now(), JSON.stringify(token));
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
        return __classPrivateFieldGet(this, _adapter).deleteKeys(entries);
    }
    confirmToken(key, password) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const result = yield __classPrivateFieldGet(this, _adapter).getKey(tokenPrefix + ':' + key);
                if (!result) {
                    throw Session.invalidMsg;
                }
                const token = JSON.parse(result);
                yield util_1.verifyPassword(token, password);
                delete token.salt;
                delete token.derived_key;
                return token;
            }
            catch (error) {
                throw Session.invalidMsg;
            }
        });
    }
    /**
     * retrieved the key from the session adapter
     */
    fetchToken(key) {
        return __classPrivateFieldGet(this, _adapter).getKey(tokenPrefix + ':' + key).then(result => {
            return Promise.resolve(JSON.parse(result));
        });
    }
    quit() {
        return __classPrivateFieldGet(this, _adapter).quit();
    }
}
exports.Session = Session;
_adapter = new WeakMap();
Session.invalidMsg = 'invalid token';
