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
var _redisClient;
Object.defineProperty(exports, "__esModule", { value: true });
const BPromise = require("bluebird");
const redis = BPromise.promisifyAll(require('redis'));
class RedisAdapter {
    constructor(config) {
        _redisClient.set(this, void 0);
        if (!config.getItem('session.redis.unix_socket')) {
            if (config.getItem('session.redis.url')) {
                __classPrivateFieldSet(this, _redisClient, redis.createClient(config.getItem('session.redis.url'), config.getItem('session.redis.options')));
            }
            else {
                __classPrivateFieldSet(this, _redisClient, redis.createClient(config.getItem('session.redis.port') || 6379, config.getItem('session.redis.host') || '127.0.0.1', config.getItem('session.redis.options')));
            }
        }
        else {
            __classPrivateFieldSet(this, _redisClient, redis.createClient(config.getItem('session.redis.unix_socket'), config.getItem('session.redis.options')));
        }
        // Authenticate with Redis if necessary
        if (config.getItem('session.redis.password')) {
            __classPrivateFieldGet(this, _redisClient).authAsync(config.getItem('session.redis.password'))
                .catch(err => {
                throw new Error(err);
            });
        }
        __classPrivateFieldGet(this, _redisClient).on('error', err => {
            console.error('Redis error: ' + err);
        });
        __classPrivateFieldGet(this, _redisClient).on('connect', () => {
            console.log('Redis is ready');
        });
    }
    storeKey(key, life, data) {
        return __classPrivateFieldGet(this, _redisClient).psetexAsync(key, life, data);
    }
    deleteKeys(keys) {
        return __classPrivateFieldGet(this, _redisClient).delAsync(keys);
    }
    getKey(key) {
        return __classPrivateFieldGet(this, _redisClient).getAsync(key);
    }
    quit() {
        return __classPrivateFieldGet(this, _redisClient).quit();
    }
}
exports.RedisAdapter = RedisAdapter;
_redisClient = new WeakMap();
