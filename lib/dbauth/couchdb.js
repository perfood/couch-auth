'use strict';
var util = require('../util');
var securityPlugin = require('pouchdb-security-helper');
var PouchDB = require('pouchdb');
PouchDB.plugin(securityPlugin);

const userPrefix = 'org.couchdb.user:';

class CouchAdapter {
  #couchAuthDB;
  constructor(couchAuthDB) {
    this.#couchAuthDB = couchAuthDB;
  }

  storeKey(username, key, password, expires, roles, provider) {
    if (roles instanceof Array) {
      // Clone roles to not overwrite original
      roles = roles.slice(0);
    } else {
      roles = [];
    }
    roles.unshift('user:' + username);
    var newKey = {
      _id: userPrefix + key,
      type: 'user',
      name: key,
      user_id: username,
      password: password,
      expires: expires,
      roles: roles,
      provider: provider
    };
    return this.#couchAuthDB.put(newKey).then(() => {
      newKey._id = key;
      return Promise.resolve(newKey);
    });
  }

  /** fetches the document from the couchAuthDB, if it's present. Throws an error otherwise. */
  retrieveKey(key) {
    return this.#couchAuthDB.get(userPrefix + key);
  }

  /**
   * Removes the keys of format org.couchdb.user:TOKEN from the `_users` - database, if they are present.
   * @param {string[]} keys
   */
  removeKeys(keys) {
    keys = util.toArray(keys);
    var keylist = [];
    // Transform the list to contain the CouchDB _user ids
    keys.forEach(key => {
      keylist.push(userPrefix + key);
    });
    var toDelete = [];
    return this.#couchAuthDB.allDocs({ keys: keylist }).then(keyDocs => {
      keyDocs.rows.forEach(row => {
        if (!row.error && !row.value.deleted) {
          var deletion = {
            _id: row.id,
            _rev: row.value.rev,
            _deleted: true
          };
          toDelete.push(deletion);
        }
      });
      if (toDelete.length) {
        return this.#couchAuthDB.bulkDocs(toDelete);
      } else {
        return Promise.resolve(false);
      }
    });
  }

  initSecurity(db, adminRoles, memberRoles) {
    var changes = false;
    return db.get('_security').then(secDoc => {
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
        return this.putSecurityCouch(db, secDoc);
      } else {
        return Promise.resolve(false);
      }
    });
  }

  authorizeKeys(user_id, db, keys) {
    var secDoc;
    // Check if keys is an object and convert it to an array
    if (typeof keys === 'object' && !(keys instanceof Array)) {
      var keysArr = [];
      Object.keys(keys).forEach(theKey => {
        keysArr.push(theKey);
      });
      keys = keysArr;
    }
    // Convert keys to an array if it is just a string
    keys = util.toArray(keys);
    return db.get('_security').then(doc => {
      secDoc = doc;
      if (!secDoc.members) {
        secDoc.members = { names: [], roles: [] };
      }
      if (!secDoc.members.names) {
        secDoc.members.names = [];
      }
      var changes = false;
      keys.forEach(key => {
        var index = secDoc.members.names.indexOf(key);
        if (index === -1) {
          secDoc.members.names.push(key);
          changes = true;
        }
      });
      if (changes) {
        return this.putSecurityCouch(db, secDoc);
      } else {
        return Promise.resolve(false);
      }
    });
  }

  /** removes the keys from the security doc of the db */
  deauthorizeKeys(db, keys) {
    var secDoc;
    keys = util.toArray(keys);
    return db.get('_security').then(doc => {
      secDoc = doc;
      if (!secDoc.members || !secDoc.members.names) {
        return Promise.resolve(false);
      }
      var changes = false;
      keys.forEach(key => {
        var index = secDoc.members.names.indexOf(key);
        if (index > -1) {
          secDoc.members.names.splice(index, 1);
          changes = true;
        }
      });
      if (changes) {
        return this.putSecurityCouch(db, secDoc);
      } else {
        return Promise.resolve(false);
      }
    });
  }

  putSecurityCouch(db, doc) {
    var security = db.security(doc);
    return security.save();
    //return db.putSecurity(doc);
  }
}
module.exports = CouchAdapter;
