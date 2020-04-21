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
var _couchAuthDB, _couch;
Object.defineProperty(exports, "__esModule", { value: true });
const util_1 = require("../util");
const userPrefix = 'org.couchdb.user:';
class CouchAdapter {
    constructor(couchAuthDB, couch) {
        _couchAuthDB.set(this, void 0);
        _couch.set(this, void 0);
        __classPrivateFieldSet(this, _couchAuthDB, couchAuthDB);
        __classPrivateFieldSet(this, _couch, couch);
    }
    /**
     * stores a CouchDbAuthDoc with the passed information
     */
    storeKey(username, key, password, expires, roles, provider) {
        return __awaiter(this, void 0, void 0, function* () {
            if (roles instanceof Array) {
                // Clone roles to not overwrite original
                roles = roles.slice(0);
            }
            else {
                roles = [];
            }
            roles.unshift('user:' + username);
            const newKey = {
                _id: userPrefix + key,
                type: 'user',
                name: key,
                user_id: username,
                password: password,
                expires: expires,
                roles: roles,
                provider: provider
            };
            yield __classPrivateFieldGet(this, _couchAuthDB).insert(newKey);
            newKey._id = key;
            return newKey;
        });
    }
    /**
     * fetches the document from the couchAuthDB, if it's present. Throws an error otherwise.
     */
    retrieveKey(key) {
        return __classPrivateFieldGet(this, _couchAuthDB).get(userPrefix + key);
    }
    /**
     * Removes the keys of format `org.couchdb.user:TOKEN` from the `_users` - database, if they are present.
     */
    removeKeys(keys) {
        return __awaiter(this, void 0, void 0, function* () {
            const keylist = [];
            // Transform the list to contain the CouchDB _user ids
            util_1.toArray(keys).forEach(key => {
                keylist.push(userPrefix + key);
            });
            const toDelete = [];
            // success: have row.doc, but possibly row.doc = null and row.value.deleted = true
            // failure: have row.key and row.error
            const keyDocs = yield __classPrivateFieldGet(this, _couchAuthDB).fetch({ keys: keylist });
            keyDocs.rows.forEach(row => {
                if (!('doc' in row)) {
                    console.warn('removeKeys() - could not retrieve: ' + row.key);
                }
                else if (!('deleted' in row.value)) {
                    const deletion = {
                        _id: row.doc._id,
                        _rev: row.doc._rev,
                        _deleted: true
                    };
                    toDelete.push(deletion);
                }
            });
            if (toDelete.length) {
                return __classPrivateFieldGet(this, _couchAuthDB).bulk({ docs: toDelete });
            }
            else {
                return false;
            }
        });
    }
    /**
     * initializes the `_security` doc with the passed roles
     * @param {import('nano').DocumentScope} db
     * @param {string[]} adminRoles
     * @param {string[]} memberRoles
     */
    initSecurity(db, adminRoles, memberRoles) {
        return __awaiter(this, void 0, void 0, function* () {
            let changes = false;
            const secDoc = yield db.get('_security');
            if (!secDoc.admins) {
                secDoc.admins = { names: [], roles: [] };
            }
            if (!secDoc.admins.roles) {
                secDoc.admins.roles = [];
            }
            if (!secDoc.members) {
                secDoc.members = { names: [], roles: [] };
            }
            if (!secDoc.members.roles) {
                secDoc.admins.roles = [];
            }
            adminRoles.forEach(function (role) {
                if (secDoc.admins.roles.indexOf(role) === -1) {
                    changes = true;
                    secDoc.admins.roles.push(role);
                }
            });
            memberRoles.forEach(function (role) {
                if (secDoc.members.roles.indexOf(role) === -1) {
                    changes = true;
                    secDoc.members.roles.push(role);
                }
            });
            if (changes) {
                return this.putSecurity(db, secDoc);
            }
            else {
                return false;
            }
        });
    }
    /**
     * authorises the passed keys to access the db
     */
    authorizeKeys(user_id, db, keys, permissions, roles) {
        return __awaiter(this, void 0, void 0, function* () {
            // Check if keys is an object and convert it to an array
            if (typeof keys === 'object' && !(keys instanceof Array)) {
                const keysArr = [];
                Object.keys(keys).forEach(theKey => {
                    keysArr.push(theKey);
                });
                keys = keysArr;
            }
            // Convert keys to an array if it is just a string
            keys = util_1.toArray(keys);
            const secDoc = yield db.get('_security');
            if (!secDoc.members) {
                secDoc.members = { names: [], roles: [] };
            }
            if (!secDoc.members.names) {
                secDoc.members.names = [];
            }
            let changes = false;
            keys.forEach(key => {
                const index = secDoc.members.names.indexOf(key);
                if (index === -1) {
                    secDoc.members.names.push(key);
                    changes = true;
                }
            });
            if (changes) {
                return yield this.putSecurity(db, secDoc);
            }
            else {
                return false;
            }
        });
    }
    /**
     * removes the keys from the security doc of the db
     */
    deauthorizeKeys(db, keys) {
        return __awaiter(this, void 0, void 0, function* () {
            const keysArr = util_1.toArray(keys);
            const secDoc = yield db.get('_security');
            if (!secDoc.members || !secDoc.members.names) {
                return false;
            }
            let changes = false;
            keysArr.forEach(key => {
                const index = secDoc.members.names.indexOf(key);
                if (index > -1) {
                    secDoc.members.names.splice(index, 1);
                    changes = true;
                }
            });
            if (changes) {
                return yield this.putSecurity(db, secDoc);
            }
            else {
                return false;
            }
        });
    }
    putSecurity(db, secDoc) {
        // @ts-ignore
        return __classPrivateFieldGet(this, _couch).request({
            db: db.config.db,
            method: 'put',
            doc: '_security',
            body: secDoc
        });
    }
}
exports.CouchAdapter = CouchAdapter;
_couchAuthDB = new WeakMap(), _couch = new WeakMap();
