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
var _sessionFolder;
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs-extra');
const path = require('path');
class FileAdapter {
    constructor(config) {
        _sessionFolder.set(this, void 0);
        const sessionsRoot = config.getItem('session.file.sessionsRoot');
        __classPrivateFieldSet(this, _sessionFolder, path.join(process.env.PWD, sessionsRoot));
        console.log('File Adapter loaded');
    }
    getFilepath(key) {
        return path.format({
            dir: __classPrivateFieldGet(this, _sessionFolder),
            base: key + '.json'
        });
    }
    storeKey(key, life, data) {
        const now = Date.now();
        return fs.outputJson(this.getFilepath(key), {
            data: data,
            expire: now + life
        });
    }
    getKey(key) {
        const now = Date.now();
        return fs
            .readJson(this.getFilepath(key))
            .then(session => {
            if (session.expire > now) {
                return session.data;
            }
            return false;
        })
            .catch(() => {
            return false;
        });
    }
    deleteKeys(keys) {
        if (!(keys instanceof Array)) {
            keys = [keys];
        }
        const deleteQueue = keys.map(key => {
            return fs.remove(this.getFilepath(key));
        });
        return Promise.all(deleteQueue).then(done => {
            // this._removeExpired(); todo maybe?
            return done.length;
        });
    }
    quit() {
        return Promise.resolve();
    }
}
exports.FileAdapter = FileAdapter;
_sessionFolder = new WeakMap();
