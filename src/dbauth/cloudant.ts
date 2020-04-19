'use strict';
import url from 'url';
import request from 'superagent';
import * as util from './../util';
import { DocumentScope } from 'nano';
// todo: make work with nano...

export class CloudantAdapter {
  /** not needed/ implemented for Cloudant */
  storeKey() {
    return Promise.resolve();
  }

  /** not needed/ implemented for Cloudant */
  removeKeys() {
    return Promise.resolve();
  }

  /** not needed/ implemented for Cloudant */
  initSecurity() {
    return Promise.resolve();
  }

  /** not needed/ implemented for Cloudant */
  retrieveKey(key) {
    return Promise.reject();
  }

  authorizeKeys(
    user_id: string,
    db: DocumentScope<any>,
    keys: Record<string, any> | Array<string> | string,
    permissions?: string[],
    roles?: string[]
  ) {
    let keysObj = {};
    if (!permissions) {
      permissions = ['_reader', '_replicator'];
    }
    permissions = permissions.concat(roles || []);
    permissions.unshift('user:' + user_id);
    // If keys is a single value convert it to an Array
    keys = util.toArray(keys);
    // Check if keys is an array and convert it to an object
    if (keys instanceof Array) {
      keys.forEach(key => {
        keysObj[key] = permissions;
      });
    } else {
      keysObj = keys;
    }
    // Pull the current _security doc
    return this.getSecurityCloudant(db).then(secDoc => {
      if (!secDoc._id) {
        secDoc._id = '_security';
      }
      if (!secDoc.cloudant) {
        secDoc.cloudant = {};
      }
      Object.keys(keysObj).forEach(function (key) {
        secDoc.cloudant[key] = keysObj[key];
      });
      return this.putSecurityCloudant(db, secDoc);
    });
  }

  deauthorizeKeys(db, keys) {
    // cast keys to an Array
    keys = util.toArray(keys);
    return this.getSecurityCloudant(db).then(secDoc => {
      let changes = false;
      if (!secDoc.cloudant) {
        return Promise.resolve(false);
      }
      keys.forEach(key => {
        if (secDoc.cloudant[key]) {
          changes = true;
          delete secDoc.cloudant[key];
        }
      });
      if (changes) {
        return this.putSecurityCloudant(db, secDoc);
      } else {
        return Promise.resolve(false);
      }
    });
  }

  getAPIKey(db) {
    const parsedUrl = url.parse(db.getUrl());
    parsedUrl.pathname = '/_api/v2/api_keys';
    const finalUrl = url.format(parsedUrl);
    return request
      .post(finalUrl)
      .set(db.getHeaders())
      .then(res => {
        const result = JSON.parse(res.text);
        if (result.key && result.password && result.ok === true) {
          return Promise.resolve(result);
        } else {
          return Promise.reject(result);
        }
      });
  }

  // todo: fix db, should be DocumentScope<any>, and then the headers...
  getSecurityCloudant(db: any) {
    const finalUrl = this.getSecurityUrl(db);
    return request
      .get(finalUrl)
      .set(db.getHeaders())
      .then(res => {
        return Promise.resolve(JSON.parse(res.text));
      });
  }
  putSecurityCloudant(db: any, doc) {
    const finalUrl = this.getSecurityUrl(db);
    return request
      .put(finalUrl)
      .set(db.getHeaders())
      .send(doc)
      .then(res => {
        return Promise.resolve(JSON.parse(res.text));
      });
  }

  private getSecurityUrl(db: any) {
    const parsedUrl = url.parse(db.getUrl());
    parsedUrl.pathname = parsedUrl.pathname + '_security';
    return url.format(parsedUrl);
  }
}
