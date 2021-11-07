'use strict';
import { DocumentScope, ServerScope } from 'nano';
import seed from '../design/seed';
import { Config, PersonalDBSettings, PersonalDBType } from '../types/config';
import { CouchDbAuthDoc, IdentifiedObj, SlUserDoc } from '../types/typings';
import { getSessions, toArray, URLSafeUUID } from '../util';
import { CouchAdapter } from './couchdb';

export class DBAuth {
  adapter: CouchAdapter;

  constructor(
    private config: Partial<Config>,
    private userDB: DocumentScope<SlUserDoc>,
    private couchServer: ServerScope,
    couchAuthDB?: DocumentScope<CouchDbAuthDoc>
  ) {
    this.adapter = new CouchAdapter(couchAuthDB, this.couchServer, this.config);
  }

  storeKey(
    username: string,
    user_uid: string,
    key: string,
    password: string,
    expires: number,
    roles: string[],
    provider: string
  ) {
    return this.adapter.storeKey(
      username,
      user_uid,
      key,
      password,
      expires,
      roles,
      provider
    );
  }

  /**
   * Step 1) During deauthorization: Removes the keys of format
   * org.couchdb.user:TOKEN from the `_users` - database, if they are present.
   * If this step fails, the user hasn't been deauthorized!
   */
  removeKeys(keys) {
    return this.adapter.removeKeys(keys);
  }

  retrieveKey(key: string) {
    return this.adapter.retrieveKey(key) as Promise<CouchDbAuthDoc>;
  }

  extendKey(key: string, newExpiration: number) {
    return this.adapter.extendKey(key, newExpiration);
  }

  /** generates a random token and password */
  getApiKey() {
    let token = URLSafeUUID();
    // Make sure our token doesn't start with illegal characters
    while (token[0] === '_' || token[0] === '-') {
      token = URLSafeUUID();
    }
    return {
      key: token,
      password: URLSafeUUID()
    };
  }

  async authorizeKeys(
    db: DocumentScope<any>,
    keys: Record<string, any> | Array<string> | string
  ) {
    return this.adapter.authorizeKeys(db, keys);
  }

  /** removes the keys from the security doc of the db */
  deauthorizeKeys(db: DocumentScope<any>, keys: string[] | string) {
    return this.adapter.deauthorizeKeys(db, keys);
  }

  authorizeUserSessions(personalDBs, sessionKeys: string[] | string) {
    const promises = [];
    Object.keys(personalDBs).forEach(personalDB => {
      const db = this.couchServer.use(personalDB);
      promises.push(this.authorizeKeys(db, toArray(sessionKeys)));
    });
    return Promise.all(promises);
  }

  async addUserDB(
    userDoc: SlUserDoc,
    dbName: string,
    designDocs?: any[],
    type?: string,
    adminRoles?: string[],
    memberRoles?: string[]
  ): Promise<string> {
    const promises = [];
    adminRoles = adminRoles || [];
    memberRoles = memberRoles || [];
    // Create and the database and seed it if a designDoc is specified
    const prefix = this.config.userDBs.privatePrefix
      ? this.config.userDBs.privatePrefix + '_'
      : '';

    // new in 2.0: use uuid instead of username
    const finalDBName =
      type === 'shared' ? dbName : prefix + dbName + '$' + userDoc._id;
    await this.createDB(finalDBName);
    const newDB = this.couchServer.db.use(finalDBName);
    await this.adapter.initSecurity(newDB, adminRoles, memberRoles);
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
      promises.push(this.authorizeKeys(newDB, keysToAuthorize));
    }
    await Promise.all(promises);
    return finalDBName;
  }

  /**
   * Checks from the superlogin-userDB which keys are expired and removes them
   * from:
   * 1. the CouchDB authentication-DB (`_users`)
   * 2. the security-doc of the user's personal DB
   * 3. the user's doc in the superlogin-DB
   *
   * @returns an array of removed keys
   * @throws This method can fail due to Connection/ CouchDB-Problems.
   */
  async removeExpiredKeys(): Promise<string[]> {
    const keysByUser = {};
    const userDocs = {};
    const expiredKeys: string[] = [];
    // query a list of expired keys by user
    const results = await this.userDB.view('auth', 'expiredKeys', {
      endkey: Date.now(),
      include_docs: true
    });
    // group by user
    results.rows.forEach(row => {
      const val = row.value as { key: string; user: string };
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
      await this.userDB.bulk({ docs: userUpdates });
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
        const db = this.couchServer.use(personalDB);
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
    let designDocDir = this.config.userDBs.designDocDir;
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

  getDBConfig(
    dbName: string,
    type?: PersonalDBType
  ): PersonalDBSettings & IdentifiedObj {
    const dbConfig: Partial<PersonalDBSettings & IdentifiedObj> = {
      name: dbName
    };
    dbConfig.adminRoles =
      this.config.userDBs?.defaultSecurityRoles?.admins || [];
    dbConfig.memberRoles =
      this.config.userDBs?.defaultSecurityRoles?.members || [];
    const dbConfigRef = this.config.userDBs?.model?.[dbName];
    if (dbConfigRef) {
      dbConfig.designDocs = dbConfigRef.designDocs || [];
      dbConfig.type = type || dbConfigRef.type || 'private';
      const dbAdminRoles = dbConfigRef.adminRoles;
      const dbMemberRoles = dbConfigRef.memberRoles;
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
    } else if (this.config.userDBs.model?._default) {
      // Only add the default design doc to a private database
      if (!type || type === 'private') {
        dbConfig.designDocs =
          this.config.userDBs.model._default.designDocs || [];
      } else {
        dbConfig.designDocs = [];
      }
      dbConfig.type = type || 'private';
    } else {
      dbConfig.type = type || 'private';
    }
    return dbConfig as PersonalDBSettings & IdentifiedObj;
  }

  async createDB(dbName: string) {
    try {
      await this.couchServer.db.create(dbName);
    } catch (err) {
      if (err.statusCode === 412) {
        return false; // already exists
      }
      throw err;
    }
    return true;
  }

  removeDB(dbName: string) {
    return this.couchServer.db.destroy(dbName);
  }
}
