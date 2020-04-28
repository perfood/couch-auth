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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _adapter, _config, _userDB, _couch;
Object.defineProperty(exports, "__esModule", { value: true });
const util_1 = require("../util");
const seed_1 = __importDefault(require("../design/seed"));
const superagent_1 = __importDefault(require("superagent"));
const couchdb_1 = require("./couchdb");
const cloudant_1 = require("./cloudant");
const nano_1 = __importDefault(require("nano"));
class DBAuth {
    constructor(config, userDB, couchAuthDB) {
        _adapter.set(this, void 0);
        _config.set(this, void 0);
        _userDB.set(this, void 0);
        _couch.set(this, void 0);
        __classPrivateFieldSet(this, _config, config);
        __classPrivateFieldSet(this, _userDB, userDB);
        __classPrivateFieldSet(this, _couch, nano_1.default({
            url: util_1.getDBURL(config.getItem('dbServer')),
            parseUrl: false
        }));
        const cloudant = __classPrivateFieldGet(this, _config).getItem('dbServer.cloudant');
        if (cloudant) {
            __classPrivateFieldSet(this, _adapter, new cloudant_1.CloudantAdapter());
        }
        else {
            __classPrivateFieldSet(this, _adapter, new couchdb_1.CouchAdapter(couchAuthDB, __classPrivateFieldGet(this, _couch)));
        }
    }
    storeKey(username, key, password, expires, roles, provider) {
        return __classPrivateFieldGet(this, _adapter).storeKey(username, key, password, expires, roles, provider);
    }
    /**
     * Step 1) During deauthorization: Removes the keys of format org.couchdb.user:TOKEN from the `_users` - database,
     * if they are present. If this step fails, the user hasn't been deauthorized!
     */
    removeKeys(keys) {
        return __classPrivateFieldGet(this, _adapter).removeKeys(keys);
    }
    retrieveKey(key) {
        return __classPrivateFieldGet(this, _adapter).retrieveKey(key);
    }
    authorizeKeys(user_id, db, keys, permissions, roles) {
        return __classPrivateFieldGet(this, _adapter).authorizeKeys(user_id, db, keys, permissions, roles);
    }
    /** removes the keys from the security doc of the db */
    deauthorizeKeys(db, keys) {
        return __classPrivateFieldGet(this, _adapter).deauthorizeKeys(db, keys);
    }
    authorizeUserSessions(user_id, personalDBs, sessionKeys, roles) {
        const promises = [];
        Object.keys(personalDBs).forEach(personalDB => {
            let permissions = personalDBs[personalDB].permissions;
            if (!permissions) {
                permissions =
                    __classPrivateFieldGet(this, _config).getItem('userDBs.model.' + personalDBs[personalDB].name + '.permissions') ||
                        __classPrivateFieldGet(this, _config).getItem('userDBs.model._default.permissions') ||
                        [];
            }
            const db = __classPrivateFieldGet(this, _couch).use(personalDB);
            promises.push(this.authorizeKeys(user_id, db, util_1.toArray(sessionKeys), permissions, roles));
        });
        return Promise.all(promises);
    }
    addUserDB(userDoc, dbName, designDocs, type, permissions, adminRoles, memberRoles) {
        return __awaiter(this, void 0, void 0, function* () {
            const promises = [];
            adminRoles = adminRoles || [];
            memberRoles = memberRoles || [];
            // Create and the database and seed it if a designDoc is specified
            const prefix = __classPrivateFieldGet(this, _config).getItem('userDBs.privatePrefix')
                ? __classPrivateFieldGet(this, _config).getItem('userDBs.privatePrefix') + '_'
                : '';
            // Make sure we have a legal database name
            let username = userDoc._id;
            username = this.getLegalDBName(username);
            const finalDBName = type === 'shared' ? dbName : prefix + dbName + '$' + username;
            yield this.createDB(finalDBName);
            const newDB = __classPrivateFieldGet(this, _couch).db.use(finalDBName);
            yield __classPrivateFieldGet(this, _adapter).initSecurity(newDB, adminRoles, memberRoles);
            // Seed the design docs
            if (designDocs && designDocs instanceof Array) {
                designDocs.forEach(ddName => {
                    const dDoc = this.getDesignDoc(ddName);
                    if (dDoc) {
                        promises.push(seed_1.default(newDB, dDoc));
                    }
                    else {
                        console.warn('Failed to locate design doc: ' + ddName);
                    }
                });
            }
            // Authorize the user's existing DB keys to access the new database
            const keysToAuthorize = [];
            if (userDoc.session) {
                for (const key in userDoc.session) {
                    if (userDoc.session.hasOwnProperty(key) &&
                        userDoc.session[key].expires > Date.now()) {
                        keysToAuthorize.push(key);
                    }
                }
            }
            if (keysToAuthorize.length > 0) {
                promises.push(this.authorizeKeys(userDoc._id, newDB, keysToAuthorize, permissions, userDoc.roles));
            }
            yield Promise.all(promises);
            return finalDBName;
        });
    }
    /**
     * Checks from the superlogin-userDB which keys are expired and removes them from:
     * 1. the CouchDB authentication-DB (`_users`)
     * 2. the security-doc of the user's personal DB
     * 3. the user's doc in the superlogin-DB
     * This method might fail due to Connection/ CouchDB-Problems.
     */
    removeExpiredKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            const keysByUser = {};
            const userDocs = {};
            const expiredKeys = [];
            // query a list of expired keys by user
            const results = yield __classPrivateFieldGet(this, _userDB).view('auth', 'expiredKeys', {
                endkey: Date.now(),
                include_docs: true
            });
            // group by user
            results.rows.forEach(row => {
                const val = row.value;
                keysByUser[val.user] = val.key;
                expiredKeys.push(val.key);
                // Add the user doc if it doesn't already exist
                if (typeof userDocs[val.user] === 'undefined') {
                    userDocs[val.user] = row.doc;
                }
                // remove each key from user.session
                if (userDocs[val.user].session) {
                    Object.keys(userDocs[val.user].session).forEach(session => {
                        if (val.key === session) {
                            delete userDocs[val.user].session[session];
                        }
                    });
                }
            });
            if (expiredKeys.length > 0) {
                // 1. remove from `_users` s.t. access is blocked.
                yield this.removeKeys(expiredKeys);
                for (const user of Object.keys(keysByUser)) {
                    // 2. deauthorize from the user's personal DB. Not necessary for Session Adapter.
                    yield this.deauthorizeUser(userDocs[user], keysByUser[user]);
                }
                const userUpdates = [];
                Object.keys(userDocs).forEach(user => {
                    userUpdates.push(userDocs[user]);
                });
                // 3. save the changes to the SL-doc
                yield __classPrivateFieldGet(this, _userDB).bulk({ docs: userUpdates });
            }
            return expiredKeys;
        });
    }
    /** deauthenticates the keys from the user's personal DB */
    deauthorizeUser(userDoc, keys) {
        const promises = [];
        // If keys is not specified we will deauthorize all of the users sessions
        if (!keys) {
            keys = util_1.getSessions(userDoc);
        }
        keys = util_1.toArray(keys);
        if (userDoc.personalDBs && typeof userDoc.personalDBs === 'object') {
            Object.keys(userDoc.personalDBs).forEach(personalDB => {
                const db = __classPrivateFieldGet(this, _couch).use(personalDB);
                promises.push(this.deauthorizeKeys(db, keys));
            });
            return Promise.all(promises);
        }
        else {
            return Promise.resolve(false);
        }
    }
    getDesignDoc(docName) {
        if (!docName) {
            return null;
        }
        let designDoc;
        let designDocDir = __classPrivateFieldGet(this, _config).getItem('userDBs.designDocDir');
        if (!designDocDir) {
            designDocDir = __dirname;
        }
        try {
            designDoc = require(designDocDir + '/' + docName);
        }
        catch (err) {
            console.warn('Design doc: ' + designDocDir + '/' + docName + ' not found.');
            designDoc = null;
        }
        return designDoc;
    }
    getDBConfig(dbName, type) {
        const dbConfig = {
            name: dbName
        };
        dbConfig.adminRoles =
            __classPrivateFieldGet(this, _config).getItem('userDBs.defaultSecurityRoles.admins') || [];
        dbConfig.memberRoles =
            __classPrivateFieldGet(this, _config).getItem('userDBs.defaultSecurityRoles.members') || [];
        const dbConfigRef = 'userDBs.model.' + dbName;
        if (__classPrivateFieldGet(this, _config).getItem(dbConfigRef)) {
            dbConfig.permissions =
                __classPrivateFieldGet(this, _config).getItem(dbConfigRef + '.permissions') || [];
            dbConfig.designDocs =
                __classPrivateFieldGet(this, _config).getItem(dbConfigRef + '.designDocs') || [];
            dbConfig.type =
                type || __classPrivateFieldGet(this, _config).getItem(dbConfigRef + '.type') || 'private';
            const dbAdminRoles = __classPrivateFieldGet(this, _config).getItem(dbConfigRef + '.adminRoles');
            const dbMemberRoles = __classPrivateFieldGet(this, _config).getItem(dbConfigRef + '.memberRoles');
            if (dbAdminRoles && dbAdminRoles instanceof Array) {
                dbAdminRoles.forEach(role => {
                    if (role && dbConfig.adminRoles.indexOf(role) === -1) {
                        dbConfig.adminRoles.push(role);
                    }
                });
            }
            if (dbMemberRoles && dbMemberRoles instanceof Array) {
                dbMemberRoles.forEach(role => {
                    if (role && dbConfig.memberRoles.indexOf(role) === -1) {
                        dbConfig.memberRoles.push(role);
                    }
                });
            }
        }
        else if (__classPrivateFieldGet(this, _config).getItem('userDBs.model._default')) {
            dbConfig.permissions =
                __classPrivateFieldGet(this, _config).getItem('userDBs.model._default.permissions') || [];
            // Only add the default design doc to a private database
            if (!type || type === 'private') {
                dbConfig.designDocs =
                    __classPrivateFieldGet(this, _config).getItem('userDBs.model._default.designDocs') || [];
            }
            else {
                dbConfig.designDocs = [];
            }
            dbConfig.type = type || 'private';
        }
        else {
            dbConfig.type = type || 'private';
        }
        return dbConfig;
    }
    createDB(dbName) {
        const finalUrl = util_1.getDBURL(__classPrivateFieldGet(this, _config).getItem('dbServer')) + '/' + dbName;
        return superagent_1.default
            .put(finalUrl)
            .send({})
            .then(res => {
            return Promise.resolve(JSON.parse(res.text));
        }, err => {
            if (err.status === 412) {
                return Promise.resolve(false);
            }
            else {
                return Promise.reject(err.text);
            }
        });
    }
    removeDB(dbName) {
        return __classPrivateFieldGet(this, _couch).db.destroy(dbName);
    }
    getLegalDBName(input) {
        input = input.toLowerCase();
        let output = encodeURIComponent(input);
        output = output.replace(/\./g, '%2E');
        output = output.replace(/!/g, '%21');
        output = output.replace(/~/g, '%7E');
        output = output.replace(/\*/g, '%2A');
        output = output.replace(/'/g, '%27');
        output = output.replace(/\(/g, '%28');
        output = output.replace(/\)/g, '%29');
        output = output.replace(/\-/g, '%2D');
        output = output.toLowerCase();
        output = output.replace(/(%..)/g, function (esc) {
            esc = esc.substr(1);
            return '(' + esc + ')';
        });
        return output;
    }
}
exports.DBAuth = DBAuth;
_adapter = new WeakMap(), _config = new WeakMap(), _userDB = new WeakMap(), _couch = new WeakMap();
