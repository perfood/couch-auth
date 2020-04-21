'use strict';
import { getDBURL, toArray, getSessions } from '../util';
import seed from '../design/seed';
import request from 'superagent';
import { CouchAdapter } from './couchdb';
import { CloudantAdapter } from './cloudant';
import nano, { DocumentScope, ServerScope } from 'nano';
import { SlUserDoc, CouchDbAuthDoc, IdentifiedObj } from '../types/typings';
import { ConfigHelper } from '../config/configure';
import { PersonalDBSettings } from 'config';

export class DBAuth {
  #adapter: CouchAdapter | CloudantAdapter;
  #config: ConfigHelper;
  #userDB: DocumentScope<SlUserDoc>;
  #couch: ServerScope;

  constructor(
    config: ConfigHelper,
    userDB: DocumentScope<SlUserDoc>,
    couchAuthDB: DocumentScope<CouchDbAuthDoc>
  ) {
    this.#config = config;
    this.#userDB = userDB;
    this.#couch = nano(getDBURL(config.getItem('dbServer')));
    const cloudant = this.#config.getItem('dbServer.cloudant');
    if (cloudant) {
      this.#adapter = new CloudantAdapter();
    } else {
      this.#adapter = new CouchAdapter(couchAuthDB, this.#couch);
    }
  }

  storeKey(
    username: string,
    key: string,
    password: string,
    expires: number,
    roles: string[],
    provider: string
  ) {
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

  retrieveKey(key: string) {
    return this.#adapter.retrieveKey(key);
  }

  authorizeKeys(
    user_id: string,
    db: DocumentScope<any>,
    keys: Record<string, any> | Array<string> | string,
    permissions?,
    roles?
  ) {
    return this.#adapter.authorizeKeys(user_id, db, keys, permissions, roles);
  }

  /** removes the keys from the security doc of the db */
  deauthorizeKeys(db: DocumentScope<any>, keys: string[] | string) {
    return this.#adapter.deauthorizeKeys(db, keys);
  }

  authorizeUserSessions(
    user_id: string,
    personalDBs,
    sessionKeys: string[] | string,
    roles: string[]
  ) {
    const promises = [];
    Object.keys(personalDBs).forEach(personalDB => {
      let permissions = personalDBs[personalDB].permissions;
      if (!permissions) {
        permissions =
          this.#config.getItem(
            'userDBs.model.' + personalDBs[personalDB].name + '.permissions'
          ) ||
          this.#config.getItem('userDBs.model._default.permissions') ||
          [];
      }
      const db = this.#couch.use(personalDB);
      promises.push(
        this.authorizeKeys(
          user_id,
          db,
          toArray(sessionKeys),
          permissions,
          roles
        )
      );
    });
    return Promise.all(promises);
  }

  async addUserDB(
    userDoc: SlUserDoc,
    dbName: string,
    designDocs?: any[],
    type?: string,
    permissions?: any,
    adminRoles?: string[],
    memberRoles?: string[]
  ) {
    const promises = [];
    adminRoles = adminRoles || [];
    memberRoles = memberRoles || [];
    // Create and the database and seed it if a designDoc is specified
    const prefix = this.#config.getItem('userDBs.privatePrefix')
      ? this.#config.getItem('userDBs.privatePrefix') + '_'
      : '';

    // Make sure we have a legal database name
    let username = userDoc._id;
    username = this.getLegalDBName(username);
    const finalDBName =
      type === 'shared' ? dbName : prefix + dbName + '$' + username;
    await this.createDB(finalDBName);
    const newDB = this.#couch.db.use(finalDBName);
    await this.#adapter.initSecurity(newDB, adminRoles, memberRoles);
    // Seed the design docs
    if (designDocs && designDocs instanceof Array) {
      designDocs.forEach(ddName => {
        const dDoc = this.getDesignDoc(ddName);
        if (dDoc) {
          promises.push(seed(newDB, dDoc));
        } else {
          console.warn('Failed to locate design doc: ' + ddName);
        }
      });
    }
    // Authorize the user's existing DB keys to access the new database
    const keysToAuthorize = [];
    if (userDoc.session) {
      for (const key in userDoc.session) {
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
    await Promise.all(promises);
    return finalDBName;
  }

  /**
   * Checks from the superlogin-userDB which keys are expired and removes them from:
   * 1. the CouchDB authentication-DB (`_users`)
   * 2. the security-doc of the user's personal DB
   * 3. the user's doc in the superlogin-DB
   */
  async removeExpiredKeys() {
    const keysByUser = {};
    const userDocs = {};
    const expiredKeys = [];
    // query a list of expired keys by user
    const results = await this.#userDB.view('auth', 'expiredKeys', {
      endkey: Date.now(),
      include_docs: true
    });
    // group by user
    results.rows.forEach(row => {
      const val: any = row.value;
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
    await this.removeKeys(expiredKeys);
    // console.log('2.) deauthorize keys for each personal database of each user ')
    for (const user of Object.keys(keysByUser)) {
      await this.deauthorizeUser(userDocs[user], keysByUser[user]);
    }

    const userUpdates = [];
    Object.keys(userDocs).forEach(user => {
      userUpdates.push(userDocs[user]);
    });
    // console.log('3.) saving updates in superlogin db');
    await this.#userDB.bulk({ docs: userUpdates });
    return expiredKeys;
  }

  /** deauthenticates the keys from the user's personal DB */
  deauthorizeUser(userDoc: SlUserDoc, keys) {
    const promises = [];
    // If keys is not specified we will deauthorize all of the users sessions
    if (!keys) {
      keys = getSessions(userDoc);
    }
    keys = toArray(keys);
    if (userDoc.personalDBs && typeof userDoc.personalDBs === 'object') {
      Object.keys(userDoc.personalDBs).forEach(personalDB => {
        const db = this.#couch.use(personalDB);
        promises.push(this.deauthorizeKeys(db, keys));
      });
      return Promise.all(promises);
    } else {
      return Promise.resolve(false);
    }
  }

  getDesignDoc(docName: string) {
    if (!docName) {
      return null;
    }
    let designDoc;
    let designDocDir = this.#config.getItem('userDBs.designDocDir');
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

  getDBConfig(dbName, type?): PersonalDBSettings & IdentifiedObj {
    const dbConfig: any = {
      name: dbName
    };
    dbConfig.adminRoles =
      this.#config.getItem('userDBs.defaultSecurityRoles.admins') || [];
    dbConfig.memberRoles =
      this.#config.getItem('userDBs.defaultSecurityRoles.members') || [];
    const dbConfigRef = 'userDBs.model.' + dbName;
    if (this.#config.getItem(dbConfigRef)) {
      dbConfig.permissions =
        this.#config.getItem(dbConfigRef + '.permissions') || [];
      dbConfig.designDocs =
        this.#config.getItem(dbConfigRef + '.designDocs') || [];
      dbConfig.type =
        type || this.#config.getItem(dbConfigRef + '.type') || 'private';
      const dbAdminRoles = this.#config.getItem(dbConfigRef + '.adminRoles');
      const dbMemberRoles = this.#config.getItem(dbConfigRef + '.memberRoles');
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

  createDB(dbName: string): Promise<any> {
    const finalUrl = getDBURL(this.#config.getItem('dbServer')) + '/' + dbName;
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

  removeDB(dbName: string) {
    return this.#couch.db.destroy(dbName);
  }

  private getLegalDBName(input: string) {
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

// Escapes any characters that are illegal in a CouchDB database name using percent codes inside parenthesis
// Example: 'My.name@example.com' => 'my(2e)name(40)example(2e)com'
