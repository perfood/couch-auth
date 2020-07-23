'use strict';
import {
  CouchDbAuthDoc,
  DocumentScope,
  IdentifiedObj,
  ServerScope,
  SlUserDoc
} from '../types/typings';
import { getSessions, loadCouchServer, toArray, URLSafeUUID } from '../util';
import { CloudantAdapter } from './cloudant';
import { ConfigHelper } from '../config/configure';
import { CouchAdapter } from './couchdb';
import { PersonalDBSettings } from '../types/config';
import seed from '../design/seed';

export class DBAuth {
  #adapter: CouchAdapter | CloudantAdapter;
  #config: ConfigHelper;
  #userDB: DocumentScope<SlUserDoc>;
  #server: ServerScope;

  constructor(
    config: ConfigHelper,
    userDB: DocumentScope<SlUserDoc>,
    couchAuthDB?: DocumentScope<CouchDbAuthDoc>
  ) {
    this.#config = config;
    this.#userDB = userDB;
    this.#server = loadCouchServer(config.config);

    const cloudant = this.#config.getItem('dbServer.cloudant');
    if (cloudant) {
      this.#adapter = new CloudantAdapter(this.#config.config);
    } else {
      this.#adapter = new CouchAdapter(
        couchAuthDB,
        this.#server,
        this.#config.config
      );
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

  /**
   * Step 1) During deauthorization: Removes the keys of format org.couchdb.user:TOKEN from the `_users` - database,
   * if they are present. If this step fails, the user hasn't been deauthorized!
   */
  removeKeys(keys) {
    return this.#adapter.removeKeys(keys);
  }

  retrieveKey(key: string) {
    return this.#adapter.retrieveKey(key);
  }

  /** generates a random token and password (CouchDB) or retrieves from Cloudant */
  getApiKey() {
    if (this.#config.getItem('dbServer.cloudant')) {
      return (this.#adapter as CloudantAdapter).getAPIKey();
    } else {
      let token = URLSafeUUID();
      // Make sure our token doesn't start with illegal characters
      while (token[0] === '_' || token[0] === '-') {
        token = URLSafeUUID();
      }
      return Promise.resolve({
        key: token,
        password: URLSafeUUID()
      });
    }
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
      const db = this.#server.use(personalDB);
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
    const newDB = this.#server.db.use(finalDBName);
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
   * This method might fail due to Connection/ CouchDB-Problems.
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
    if (expiredKeys.length > 0) {
      // 1. remove from `_users` s.t. access is blocked.
      // TODO: clean up properly if not in `_users` but in roles
      await this.removeKeys(expiredKeys);
      for (const user of Object.keys(keysByUser)) {
        // 2. deauthorize from the user's personal DB. Not necessary for Session Adapter here.
        await this.deauthorizeUser(userDocs[user], keysByUser[user]);
      }

      const userUpdates = [];
      Object.keys(userDocs).forEach(user => {
        userUpdates.push(userDocs[user]);
      });
      // 3. save the changes to the SL-doc
      await this.#userDB.bulk({ docs: userUpdates });
    }
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
        const db = this.#server.use(personalDB);
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

  async createDB(dbName: string) {
    try {
      await this.#server.db.create(dbName);
    } catch (err) {
      if (err.statusCode === 412) {
        return false; // already exists
      }
      throw err;
    }
    return true;
  }

  removeDB(dbName: string) {
    return this.#server.db.destroy(dbName);
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
