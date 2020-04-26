'use strict';
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _couch;
Object.defineProperty(exports, "__esModule", { value: true });
const nano_1 = __importDefault(require("nano"));
const util_1 = require("./../util");
// todo: make work with nano...
class CloudantAdapter {
    constructor() {
        _couch.set(this, void 0);
        __classPrivateFieldSet(this, _couch, nano_1.default(util_1.getCloudantURL()));
    }
    /** not needed/ implemented for Cloudant */
    storeKey() {
        return Promise.resolve();
    }
    /** not needed/ implemented for Cloudant */
    removeKeys() {
        return Promise.resolve();
    }
    /** not needed/ implemented for Cloudant */
    initSecurity() {
        return Promise.resolve();
    }
    /** not needed/ implemented for Cloudant */
    retrieveKey(key) {
        return Promise.reject();
    }
    authorizeKeys(user_id, db, keys, permissions, roles) {
        let keysObj = {};
        if (!permissions) {
            permissions = ['_reader', '_replicator'];
        }
        permissions = permissions.concat(roles || []);
        permissions.unshift('user:' + user_id);
        // If keys is a single value convert it to an Array
        keys = util_1.toArray(keys);
        // Check if keys is an array and convert it to an object
        if (keys instanceof Array) {
            keys.forEach(key => {
                keysObj[key] = permissions;
            });
        }
        else {
            keysObj = keys;
        }
        // Pull the current _security doc
        return this.getSecurityCloudant(db).then(secDoc => {
            if (!secDoc._id) {
                secDoc._id = '_security';
            }
            if (!secDoc.cloudant) {
                secDoc.cloudant = {};
            }
            Object.keys(keysObj).forEach(function (key) {
                secDoc.cloudant[key] = keysObj[key];
            });
            return this.putSecurityCloudant(db, secDoc);
        });
    }
    deauthorizeKeys(db, keys) {
        // cast keys to an Array
        keys = util_1.toArray(keys);
        return this.getSecurityCloudant(db).then(secDoc => {
            let changes = false;
            if (!secDoc.cloudant) {
                return Promise.resolve(false);
            }
            keys.forEach(key => {
                if (secDoc.cloudant[key]) {
                    changes = true;
                    delete secDoc.cloudant[key];
                }
            });
            if (changes) {
                return this.putSecurityCloudant(db, secDoc);
            }
            else {
                return Promise.resolve(false);
            }
        });
    }
    getAPIKey() {
        return (__classPrivateFieldGet(this, _couch).request({
            method: 'POST',
            path: '_api/v2/api_keys'
        })
            .then(result => {
            if (result.key && result.password && result.ok === true) {
                return Promise.resolve(result);
            }
            else {
                return Promise.reject(result);
            }
        }));
    }
    putSecurityCloudant(db, doc) {
        // @ts-ignore
        return __classPrivateFieldGet(this, _couch).request({
            db: db.config.db,
            method: 'PUT',
            doc: '_security',
            body: doc
        });
    }
    getSecurityCloudant(db) {
        // @ts-ignore
        return __classPrivateFieldGet(this, _couch).request({
            db: db.config.db,
            method: 'GET',
            doc: '_security'
        });
    }
}
exports.CloudantAdapter = CloudantAdapter;
_couch = new WeakMap();
