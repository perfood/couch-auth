'use strict';
import { DocumentScope, ServerScope } from 'nano';
import seed from '../design/seed';
import { Config, PersonalDBSettings, PersonalDBType } from '../types/config';
import {
  CouchDbAuthDoc,
  IdentifiedObj,
  SessionCleanupType,
  SlUserDoc
} from '../types/typings';
import { getExpiredSessions, getSessions, toArray, URLSafeUUID } from '../util';
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

  /**
   * Removes the affected from the `_users` db and from the `_security` of the
   * user's personal DBs, returning the modified `sl-users` doc
   *
   *  - 'all' -> logs out all sessions
   *  - 'other' -> logout all sessions except for 'currentSession'
   *  - 'expired' -> only logs out expired sessions
   */
  public async logoutUserSessions(
    userDoc: SlUserDoc,
    op: SessionCleanupType,
    currentSession?: string
  ): Promise<SlUserDoc> {
    let sessionsToEnd: string[];
    if (op === 'expired') {
      sessionsToEnd = getExpiredSessions(userDoc, Date.now());
    } else {
      sessionsToEnd = getSessions(userDoc);
      if (op === 'other' && currentSession) {
        sessionsToEnd = sessionsToEnd.filter(s => s !== currentSession);
      }
    }

    if (sessionsToEnd.length) {
      // 1.) Remove the keys from our couchDB auth database. Must happen first.
      await this.removeKeys(sessionsToEnd);
      // 2.) Deauthorize keys from each personal database
      await this.deauthorizeUser(userDoc, sessionsToEnd);

      sessionsToEnd.forEach(session => {
        delete userDoc.session[session];
      });
      if (Object.keys(userDoc.session).length === 0) {
        delete userDoc.session;
      }

      userDoc.inactiveSessions = [
        ...(userDoc.inactiveSessions ?? []),
        ...sessionsToEnd
      ];
    }
    return userDoc;
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
    memberRoles?: string[],
    partitioned?: boolean
  ): Promise<string> {
    const promises = [];
    adminRoles = adminRoles || [];
    memberRoles = memberRoles || [];
    partitioned = partitioned || false;
    // Create and the database and seed it if a designDoc is specified
    const prefix = this.config.userDBs.privatePrefix
      ? this.config.userDBs.privatePrefix + '_'
      : '';

    // new in 2.0: use uuid instead of username
    const finalDBName =
      type === 'shared' ? dbName : prefix + dbName + '$' + userDoc._id;
    await this.createDB(finalDBName, partitioned);
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
    const alreadyProcessedUsers: Set<string> = new Set();
    let revokedSessions: string[] = [];

    // query a list of expired keys by user
    const results = await this.userDB.view('auth', 'expiredKeys', {
      endkey: Date.now(),
      include_docs: true
    });

    // clean up expired session for each user in the results
    for (const row of results.rows) {
      const val = row.value as { key: string; user: string };
      const userId = val.user;
      if (alreadyProcessedUsers.has(userId)) {
        continue;
      }
      const sessionsBefore = Object.keys(row.doc.session ?? {});
      const userDoc = await this.logoutUserSessions(row.doc, 'expired');
      await this.userDB.insert(userDoc);
      revokedSessions = revokedSessions.concat(
        sessionsBefore.filter(s => !userDoc.session || !userDoc.session[s])
      );
      alreadyProcessedUsers.add(userId);
    }

    return revokedSessions;
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
      dbConfig.partitioned = dbConfigRef.partitioned || false;
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
      dbConfig.partitioned =
        this.config.userDBs.model._default.partitioned || false;
      dbConfig.type = type || 'private';
    } else {
      dbConfig.partitioned = false;
      dbConfig.type = type || 'private';
    }
    return dbConfig as PersonalDBSettings & IdentifiedObj;
  }

  async createDB(dbName: string, partitioned?: boolean) {
    partitioned = partitioned || false;
    try {
      await this.couchServer.db.create(dbName, { partitioned: partitioned });
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
