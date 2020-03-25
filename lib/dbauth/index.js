'use strict';
var PouchDB = require('pouchdb');
var util = require('./../util');
var seed = require('pouchdb-seed-design');
var request = require('superagent');

class DBAuth {
  #adapter;
  #config;
  #userDB;
  #couchAuthDB;
  constructor(config, userDB, couchAuthDB) {
    this.#config = config;
    this.#userDB = userDB;
    this.#couchAuthDB = couchAuthDB;
    var cloudant = this.#config.getItem('dbServer.cloudant');
    if (cloudant) {
      this.#adapter = require('./cloudant');
    } else {
      var CouchAdapter = require('./couchdb');
      this.#adapter = new CouchAdapter(couchAuthDB);
    }
  }

  storeKey(username, key, password, expires, roles, provider) {
    return this.#adapter.storeKey(
      username,
      key,
      password,
      expires,
      roles,
      provider
    );
  }

  /** Removes the keys of format org.couchdb.user:TOKEN from the `_users` - database, if they are present */
  removeKeys(keys) {
    return this.#adapter.removeKeys(keys);
  }

  retrieveKey(key) {
    return this.#adapter.retrieveKey(key);
  }

  authorizeKeys(user_id, db, keys, permissions, roles) {
    return this.#adapter.authorizeKeys(user_id, db, keys, permissions, roles);
  }

  /** removes the keys from the security doc of the db */
  deauthorizeKeys(db, keys) {
    return this.#adapter.deauthorizeKeys(db, keys);
  }

  authorizeUserSessions(user_id, personalDBs, sessionKeys, roles) {
    var promises = [];
    sessionKeys = util.toArray(sessionKeys);
    Object.keys(personalDBs).forEach(personalDB => {
      var permissions = personalDBs[personalDB].permissions;
      if (!permissions) {
        permissions =
          this.#config.getItem(
            'userDBs.model.' + personalDBs[personalDB].name + '.permissions'
          ) ||
          this.#config.getItem('userDBs.model._default.permissions') ||
          [];
      }
      var db = new PouchDB(
        util.getDBURL(this.#config.getItem('dbServer')) + '/' + personalDB
      );
      promises.push(
        this.authorizeKeys(user_id, db, sessionKeys, permissions, roles)
      );
    });
    return Promise.all(promises);
  }

  addUserDB(
    userDoc,
    dbName,
    designDocs,
    type,
    permissions,
    adminRoles,
    memberRoles
  ) {
    var promises = [];
    adminRoles = adminRoles || [];
    memberRoles = memberRoles || [];
    // Create and the database and seed it if a designDoc is specified
    var prefix = this.#config.getItem('userDBs.privatePrefix')
      ? this.#config.getItem('userDBs.privatePrefix') + '_'
      : '';

    var finalDBName, newDB;
    // Make sure we have a legal database name
    var username = userDoc._id;
    username = getLegalDBName(username);
    if (type === 'shared') {
      finalDBName = dbName;
    } else {
      finalDBName = prefix + dbName + '$' + username;
    }
    return this.createDB(finalDBName)
      .then(() => {
        newDB = new PouchDB(
          util.getDBURL(this.#config.getItem('dbServer')) + '/' + finalDBName
        );
        return this.#adapter.initSecurity(newDB, adminRoles, memberRoles);
      })
      .then(() => {
        // Seed the design docs
        if (designDocs && designDocs instanceof Array) {
          designDocs.forEach(ddName => {
            var dDoc = this.getDesignDoc(ddName);
            if (dDoc) {
              promises.push(seed(newDB, dDoc));
            } else {
              console.warn('Failed to locate design doc: ' + ddName);
            }
          });
        }
        // Authorize the user's existing DB keys to access the new database
        var keysToAuthorize = [];
        if (userDoc.session) {
          for (var key in userDoc.session) {
            if (
              userDoc.session.hasOwnProperty(key) &&
              userDoc.session[key].expires > Date.now()
            ) {
              keysToAuthorize.push(key);
            }
          }
        }
        if (keysToAuthorize.length > 0) {
          promises.push(
            this.authorizeKeys(
              userDoc._id,
              newDB,
              keysToAuthorize,
              permissions,
              userDoc.roles
            )
          );
        }
        return Promise.all(promises);
      })
      .then(ret => {
        return Promise.resolve(finalDBName);
      });
  }

  /**
   * Checks from the superlogin-userDB which keys are expired and removes them from:
   * 1. the CouchDB authentication-DB (`_users`)
   * 2. the security-doc of the user's personal DB
   * 3. the user's doc in the superlogin-DB
   */
  removeExpiredKeys() {
    var keysByUser = {};
    var userDocs = {};
    var expiredKeys = [];
    // query a list of expired keys by user
    return this.#userDB
      .query('auth/expiredKeys', { endkey: Date.now(), include_docs: true })
      .then(results => {
        // group by user
        results.rows.forEach(row => {
          keysByUser[row.value.user] = row.value.key;
          expiredKeys.push(row.value.key);
          // Add the user doc if it doesn't already exist
          if (typeof userDocs[row.value.user] === 'undefined') {
            userDocs[row.value.user] = row.doc;
          }
          // remove each key from user.session
          if (userDocs[row.value.user].session) {
            Object.keys(userDocs[row.value.user].session).forEach(session => {
              if (row.value.key === session) {
                delete userDocs[row.value.user].session[session];
              }
            });
          }
        });
        return this.removeKeys(expiredKeys);
      })
      .then(async () => {
        // console.log('2.) deauthorize keys for each personal database of each user ') // in sequence!
        for (const user of Object.keys(keysByUser)) {
          await this.deauthorizeUser(userDocs[user], keysByUser[user]);
        }
      })
      .then(() => {
        var userUpdates = [];
        Object.keys(userDocs).forEach(user => {
          userUpdates.push(userDocs[user]);
        });
        // console.log('3.) saving updates in superlogin db');
        return this.#userDB.bulkDocs(userUpdates);
      })
      .then(() => {
        return Promise.resolve(expiredKeys);
      });
  }

  /** deauthenticates the keys from the user's personal DB */
  deauthorizeUser(userDoc, keys) {
    var promises = [];
    // If keys is not specified we will deauthorize all of the users sessions
    if (!keys) {
      keys = util.getSessions(userDoc);
    }
    keys = util.toArray(keys);
    if (userDoc.personalDBs && typeof userDoc.personalDBs === 'object') {
      Object.keys(userDoc.personalDBs).forEach(personalDB => {
        var db = new PouchDB(
          util.getDBURL(this.#config.getItem('dbServer')) + '/' + personalDB
        );
        promises.push(this.deauthorizeKeys(db, keys));
      });
      return Promise.all(promises);
    } else {
      return Promise.resolve(false);
    }
  }

  getDesignDoc(docName) {
    if (!docName) {
      return null;
    }
    var designDoc;
    var designDocDir = this.#config.getItem('userDBs.designDocDir');
    if (!designDocDir) {
      designDocDir = __dirname;
    }
    try {
      designDoc = require(designDocDir + '/' + docName);
    } catch (err) {
      console.warn(
        'Design doc: ' + designDocDir + '/' + docName + ' not found.'
      );
      designDoc = null;
    }
    return designDoc;
  }

  getDBConfig(dbName, type) {
    var dbConfig = {
      name: dbName
    };
    dbConfig.adminRoles =
      this.#config.getItem('userDBs.defaultSecurityRoles.admins') || [];
    dbConfig.memberRoles =
      this.#config.getItem('userDBs.defaultSecurityRoles.members') || [];
    var dbConfigRef = 'userDBs.model.' + dbName;
    if (this.#config.getItem(dbConfigRef)) {
      dbConfig.permissions =
        this.#config.getItem(dbConfigRef + '.permissions') || [];
      dbConfig.designDocs =
        this.#config.getItem(dbConfigRef + '.designDocs') || [];
      dbConfig.type =
        type || this.#config.getItem(dbConfigRef + '.type') || 'private';
      var dbAdminRoles = this.#config.getItem(dbConfigRef + '.adminRoles');
      var dbMemberRoles = this.#config.getItem(dbConfigRef + '.memberRoles');
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
    } else if (this.#config.getItem('userDBs.model._default')) {
      dbConfig.permissions =
        this.#config.getItem('userDBs.model._default.permissions') || [];
      // Only add the default design doc to a private database
      if (!type || type === 'private') {
        dbConfig.designDocs =
          this.#config.getItem('userDBs.model._default.designDocs') || [];
      } else {
        dbConfig.designDocs = [];
      }
      dbConfig.type = type || 'private';
    } else {
      dbConfig.type = type || 'private';
    }
    return dbConfig;
  }

  createDB(dbName) {
    var finalUrl =
      util.getDBURL(this.#config.getItem('dbServer')) + '/' + dbName;
    return request
      .put(finalUrl)
      .send({})
      .then(
        res => {
          return Promise.resolve(JSON.parse(res.text));
        },
        err => {
          if (err.status === 412) {
            return Promise.resolve(false);
          } else {
            return Promise.reject(err.text);
          }
        }
      );
  }

  removeDB(dbName) {
    var db = new PouchDB(
      util.getDBURL(this.#config.getItem('dbServer')) + '/' + dbName
    );
    return db.destroy();
  }
}

// Escapes any characters that are illegal in a CouchDB database name using percent codes inside parenthesis
// Example: 'My.name@example.com' => 'my(2e)name(40)example(2e)com'
function getLegalDBName(input) {
  input = input.toLowerCase();
  var output = encodeURIComponent(input);
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

module.exports = DBAuth;
