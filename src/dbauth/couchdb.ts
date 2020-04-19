'use strict';

import { DocumentScope, ServerScope } from 'nano';
import { CouchDbAuthDoc } from '../types/typings';
import { toArray } from '../util';
import { DBAdapter } from 'adapters';
const userPrefix = 'org.couchdb.user:';

export class CouchAdapter implements DBAdapter {
  #couchAuthDB: DocumentScope<CouchDbAuthDoc>;
  #couch: ServerScope;
  constructor(couchAuthDB: DocumentScope<CouchDbAuthDoc>, couch: ServerScope) {
    this.#couchAuthDB = couchAuthDB;
    this.#couch = couch;
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
    const newKey: CouchDbAuthDoc = {
      _id: userPrefix + key,
      type: 'user',
      name: key,
      user_id: username,
      password: password,
      expires: expires,
      roles: roles,
      provider: provider
    };
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
    // success: have row.doc
    // failure: have row.key and row.error
    const keyDocs = await this.#couchAuthDB.fetch({ keys: keylist });
    keyDocs.rows.forEach(row => {
      if (!('error' in row)) {
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
    const secDoc = await db.get('_security');
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
    const secDoc = await db.get('_security');
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
      return await this.putSecurity(db, secDoc);
    } else {
      return false;
    }
  }

  /**
   * removes the keys from the security doc of the db
   */
  async deauthorizeKeys(db: DocumentScope<any>, keys: string[] | string) {
    const keysArr = toArray(keys);
    const secDoc = await db.get('_security');
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
      return await this.putSecurity(db, secDoc);
    } else {
      return false;
    }
  }

  private putSecurity(db: DocumentScope<any>, secDoc) {
    // @ts-ignore
    return this.#couch.request({
      db: db.config.db,
      method: 'put',
      doc: '_security',
      body: secDoc
    });
  }
}
