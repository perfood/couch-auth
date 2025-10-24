'use strict';
import pwdModule from '@sl-nx/couch-pwd';
import { HashResult } from './types/typings';
import { Config } from './types/config';

export class SessionHashing {

  static invalidErr = { status: 401, message: 'invalid token' };

  // Hasher for hashing _users passwords
  private pwdCouch: pwdModule;
  
  constructor(config: Partial<Config>) {
    const iterations = config.security?.sessionHashing?.iterations || 1000;
    const pbkdf2_prf = config.security?.sessionHashing?.pbkdf2_prf || 'sha256';

    this.pwdCouch = new pwdModule(
      iterations,
      pbkdf2_prf == 'sha1' ? 20 : 32,
      16,
      'hex',
      pbkdf2_prf
    );
  }

  // Function for hashing _users passwords
  public hashSessionPassword(password: string): Promise<HashResult> {
    return new Promise((resolve, reject) => {
      this.pwdCouch.hash(password, (err, salt, hash) => {
        if (err) {
          return reject(err);
        }
        return resolve({
          salt: salt,
          derived_key: hash,
          password_scheme: 'pbkdf2',
          pbkdf2_prf: this.pwdCouch.digest,
          iterations: this.pwdCouch.iterations
        });
      });
    });
  }
  
  public verifySessionPassword(hashObj: HashResult, pw: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const iterations = hashObj.iterations || 10;
      const digest = hashObj.pbkdf2_prf || 'sha1';
      const length = digest === 'sha1' ? 20 : 32;
      const pwdCouch = new pwdModule(iterations, length, 16, 'hex', digest);
      
      const salt = hashObj.salt;
      const derived_key = hashObj.derived_key;
      pwdCouch.hash(pw, salt, (err, hash) => {
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
