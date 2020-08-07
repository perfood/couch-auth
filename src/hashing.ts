import { HashResult, LocalHashObj } from './types/typings';
import { Config } from './types/config';
import pwdModule from '@sl-nx/couch-pwd';

const pwd = new pwdModule();

export function hashCouchPassword(password: string): Promise<HashResult> {
  return new Promise(function (resolve, reject) {
    pwd.hash(password, function (err, salt, hash) {
      if (err) {
        return reject(err);
      }
      return resolve({
        salt: salt,
        derived_key: hash
      });
    });
  });
}
export class Hashing {
  hashers = [];
  times: number[] = [];
  constructor(config: Partial<Config>) {
    if (config.security?.iterations) {
      for (const pair of config.security.iterations) {
        this.times.push(pair[0]);
        this.hashers.push(new pwdModule(pair[1]));
      }
    }
  }

  private getHasherForTimestamp(ts: number = undefined) {
    let ret = pwd;
    if (this.times.length === 0 || ts === undefined) {
      return ret;
    }
    for (let idx = 0; idx < this.times.length; idx++) {
      if (ts > this.times[idx]) {
        ret = this.hashers[idx];
      } else {
        break;
      }
    }
    return ret;
  }

  hashUserPassword(pw: string): Promise<HashResult> {
    const t = new Date().valueOf();
    return new Promise((resolve, reject) => {
      this.getHasherForTimestamp(t).hash(pw, (err, salt, hash) => {
        if (err) {
          return reject(err);
        }
        return resolve({
          salt: salt,
          derived_key: hash
        });
      });
    }).then((hr: HashResult) => {
      hr.created = t;
      return hr;
    });
  }

  verifyUserPassword(hashObj: LocalHashObj, pw: string): Promise<boolean> {
    const salt = hashObj.salt;
    const derived_key = hashObj.derived_key;
    const t = hashObj.created;

    if (!salt || !derived_key) {
      return Promise.reject(false);
    }

    return new Promise((resolve, reject) => {
      const hasher = this.getHasherForTimestamp(t);
      hasher.hash(pw, salt, (err, hash) => {
        if (err) {
          return reject(err);
        } else if (hash !== derived_key) {
          return reject(false);
        } else {
          return resolve(true);
        }
      });
    });
  }
}
