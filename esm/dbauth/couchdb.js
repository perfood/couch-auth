'use strict';
import { getSecurityDoc, putSecurityDoc, toArray } from '../util';
import { hashCouchPassword, Hashing } from '../hashing';
const userPrefix = 'org.couchdb.user:';
export class CouchAdapter {
    constructor(couchAuthDB, couch, config) {
        var _a;
        this.couchAuthDB = couchAuthDB;
        this.couch = couch;
        this.config = config;
        this.couchAuthOnCloudant = false;
        if ((_a = this.config) === null || _a === void 0 ? void 0 : _a.dbServer.couchAuthOnCloudant) {
            this.couchAuthOnCloudant = true;
        }
        this.hasher = new Hashing(config);
    }
    /**
     * stores a CouchDbAuthDoc with the passed information. Expects the `username`
     * (i.e. `key`) and not the UUID.
     */
    async storeKey(username, key, password, expires, roles, provider) {
        if (roles instanceof Array) {
            // Clone roles to not overwrite original
            roles = roles.slice(0);
        }
        else {
            roles = [];
        }
        roles.unshift('user:' + username);
        let newKey = {
            _id: userPrefix + key,
            type: 'user',
            name: key,
            user_id: username,
            expires: expires,
            roles: roles,
            provider: provider
        };
        // required when using Cloudant or other db than `_users`
        newKey.password_scheme = 'pbkdf2';
        newKey.iterations = 10;
        newKey = {
            ...newKey,
            ...(await hashCouchPassword(password))
        };
        await this.couchAuthDB.insert(newKey);
        newKey._id = key;
        return newKey;
    }
    async extendKey(key, newExpiration) {
        const token = await this.retrieveKey(key);
        token.expires = newExpiration;
        return await this.couchAuthDB.insert(token);
    }
    /**
     * fetches the document from the couchAuthDB, if it's present. Throws an error otherwise.
     */
    retrieveKey(key) {
        return this.couchAuthDB.get(userPrefix + key);
    }
    /**
     * Removes the keys of format `org.couchdb.user:TOKEN` from the `_users` - database, if they are present.
     */
    async removeKeys(keys) {
        const keylist = [];
        // Transform the list to contain the CouchDB _user ids
        toArray(keys).forEach(key => {
            keylist.push(userPrefix + key);
        });
        const toDelete = [];
        // success: have row.doc, but possibly row.doc = null and row.value.deleted = true
        // failure: have row.key and row.error
        const keyDocs = await this.couchAuthDB.fetch({ keys: keylist });
        keyDocs.rows.forEach(row => {
            if (!('doc' in row)) {
                console.info('removeKeys() - could not retrieve: ' + row.key);
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
            return this.couchAuthDB.bulk({ docs: toDelete });
        }
        else {
            return false;
        }
    }
    /**
     * initializes the `_security` doc with the passed roles
     * @param {import('nano').DocumentScope} db
     * @param {string[]} adminRoles
     * @param {string[]} memberRoles
     */
    async initSecurity(db, adminRoles, memberRoles) {
        let changes = false;
        const secDoc = await getSecurityDoc(this.couch, db);
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
        if (this.couchAuthOnCloudant && !secDoc.couchdb_auth_only) {
            changes = true;
            secDoc.couchdb_auth_only = true;
        }
        if (changes) {
            return putSecurityDoc(this.couch, db, secDoc);
        }
        else {
            return false;
        }
    }
    /**
     * authorises the passed keys to access the db
     */
    async authorizeKeys(db, keys) {
        // Check if keys is an object and convert it to an array
        if (typeof keys === 'object' && !(keys instanceof Array)) {
            const keysArr = [];
            Object.keys(keys).forEach(theKey => {
                keysArr.push(theKey);
            });
            keys = keysArr;
        }
        // Convert keys to an array if it is just a string
        keys = toArray(keys);
        const secDoc = await getSecurityDoc(this.couch, db);
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
            return await putSecurityDoc(this.couch, db, secDoc);
        }
        else {
            return false;
        }
    }
    /**
     * removes the keys from the security doc of the db
     */
    async deauthorizeKeys(db, keys) {
        const keysArr = toArray(keys);
        const secDoc = await getSecurityDoc(this.couch, db);
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
            return await putSecurityDoc(this.couch, db, secDoc);
        }
        else {
            return false;
        }
    }
}
