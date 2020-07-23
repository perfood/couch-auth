'use strict';
import { DocumentScope, ServerScope } from 'nano';
import { getSecurityDoc, hashPassword, putSecurityDoc, toArray } from '../util';
import { Config } from '../types/config';
import { CouchDbAuthDoc } from '../types/typings';
import { DBAdapter } from '../types/adapters';

const userPrefix = 'org.couchdb.user:';

export class CouchAdapter implements DBAdapter {
  #couchAuthDB: DocumentScope<CouchDbAuthDoc>;
  #couch: ServerScope;
  #config: Partial<Config>;
  couchAuthOnCloudant = false;
  constructor(
    couchAuthDB: DocumentScope<CouchDbAuthDoc>,
    couch: ServerScope,
    config: Partial<Config>
  ) {
    this.#couchAuthDB = couchAuthDB;
    this.#couch = couch;
    this.#config = config;
    if (this.#config?.dbServer.couchAuthOnCloudant) {
      this.couchAuthOnCloudant = true;
    }
  }

  /**
   * stores a CouchDbAuthDoc with the passed information
   */
  async storeKey(
    username: string,
    key: string,
    password: string,
    expires: number,
    roles: string[],
    provider: string
  ) {
    if (roles instanceof Array) {
      // Clone roles to not overwrite original
      roles = roles.slice(0);
    } else {
      roles = [];
    }
    roles.unshift('user:' + username);
    let newKey: CouchDbAuthDoc = {
      _id: userPrefix + key,
      type: 'user',
      name: key,
      user_id: username,
      expires: expires,
      roles: roles,
      provider: provider
    };
    if (this.couchAuthOnCloudant) {
      // PWs need to be hashed manually when using pbkdf2
      newKey.password_scheme = 'pbkdf2';
      newKey.iterations = 10;
      newKey = { ...newKey, ...(await hashPassword(password)) };
    } else {
      newKey.password = password;
    }
    await this.#couchAuthDB.insert(newKey);
    newKey._id = key;
    return newKey;
  }

  /**
   * fetches the document from the couchAuthDB, if it's present. Throws an error otherwise.
   */
  retrieveKey(key: string) {
    return this.#couchAuthDB.get(userPrefix + key);
  }

  /**
   * Removes the keys of format `org.couchdb.user:TOKEN` from the `_users` - database, if they are present.
   */
  async removeKeys(keys: string[]) {
    const keylist: string[] = [];
    // Transform the list to contain the CouchDB _user ids
    toArray(keys).forEach(key => {
      keylist.push(userPrefix + key);
    });
    const toDelete: { _id: string; _rev: string; _deleted: boolean }[] = [];
    // success: have row.doc, but possibly row.doc = null and row.value.deleted = true
    // failure: have row.key and row.error
    const keyDocs = await this.#couchAuthDB.fetch({ keys: keylist });
    keyDocs.rows.forEach(row => {
      if (!('doc' in row)) {
        console.info('removeKeys() - could not retrieve: ' + row.key);
      } else if (!('deleted' in row.value)) {
        const deletion = {
          _id: row.doc._id,
          _rev: row.doc._rev,
          _deleted: true
        };
        toDelete.push(deletion);
      }
    });
    if (toDelete.length) {
      return this.#couchAuthDB.bulk({ docs: toDelete });
    } else {
      return false;
    }
  }

  /**
   * initializes the `_security` doc with the passed roles
   * @param {import('nano').DocumentScope} db
   * @param {string[]} adminRoles
   * @param {string[]} memberRoles
   */
  async initSecurity(
    db: DocumentScope<any>,
    adminRoles: string[],
    memberRoles: string[]
  ) {
    let changes = false;
    const secDoc = await getSecurityDoc(this.#couch, db);
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
      return putSecurityDoc(this.#couch, db, secDoc);
    } else {
      return false;
    }
  }

  /**
   * authorises the passed keys to access the db
   */
  async authorizeKeys(
    user_id: string,
    db: DocumentScope<any>,
    keys: Record<string, any> | Array<string> | string,
    permissions?,
    roles?
  ) {
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
    const secDoc = await getSecurityDoc(this.#couch, db);
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
      return await putSecurityDoc(this.#couch, db, secDoc);
    } else {
      return false;
    }
  }

  /**
   * removes the keys from the security doc of the db
   */
  async deauthorizeKeys(db: DocumentScope<any>, keys: string[] | string) {
    const keysArr = toArray(keys);
    const secDoc = await getSecurityDoc(this.#couch, db);
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
      return await putSecurityDoc(this.#couch, db, secDoc);
    } else {
      return false;
    }
  }
}
