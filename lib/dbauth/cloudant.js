'use strict';
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const url_1 = __importDefault(require("url"));
const superagent_1 = __importDefault(require("superagent"));
const util_1 = require("./../util");
// todo: make work with nano...
class CloudantAdapter {
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
    getAPIKey(db) {
        const parsedUrl = url_1.default.parse(db.getUrl());
        parsedUrl.pathname = '/_api/v2/api_keys';
        const finalUrl = url_1.default.format(parsedUrl);
        return superagent_1.default
            .post(finalUrl)
            .set(db.getHeaders())
            .then(res => {
            const result = JSON.parse(res.text);
            if (result.key && result.password && result.ok === true) {
                return Promise.resolve(result);
            }
            else {
                return Promise.reject(result);
            }
        });
    }
    // todo: fix db, should be DocumentScope<any>, and then the headers...
    getSecurityCloudant(db) {
        const finalUrl = this.getSecurityUrl(db);
        return superagent_1.default
            .get(finalUrl)
            .set(db.getHeaders())
            .then(res => {
            return Promise.resolve(JSON.parse(res.text));
        });
    }
    putSecurityCloudant(db, doc) {
        const finalUrl = this.getSecurityUrl(db);
        return superagent_1.default
            .put(finalUrl)
            .set(db.getHeaders())
            .send(doc)
            .then(res => {
            return Promise.resolve(JSON.parse(res.text));
        });
    }
    getSecurityUrl(db) {
        const parsedUrl = url_1.default.parse(db.getUrl());
        parsedUrl.pathname = parsedUrl.pathname + '_security';
        return url_1.default.format(parsedUrl);
    }
}
exports.CloudantAdapter = CloudantAdapter;
