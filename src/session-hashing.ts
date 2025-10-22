'use strict';
import pwdModule from '@sl-nx/couch-pwd';
import { Config } from './types/config';
import { HashResult } from './types/typings';

export class SessionHashing {

  static invalidErr = { status: 401, message: 'invalid token' };

  // Hasher for hashing _users passwords
  private pwdCouch: pwdModule;
  
  constructor(config: Partial<Config>) {
    const iterations = config.security?.sessionHashing?.iterations || 1000;
    const pbkdf2Prf = config.security?.sessionHashing?.pbkdf2Prf || 'sha256';
    const keyLength = config.security?.sessionHashing?.keyLength || 32;
    const saltLength = config.security?.sessionHashing?.saltLength || 16;

    this.pwdCouch = new pwdModule(
      iterations,
      keyLength,
      saltLength,
      'hex',
      pbkdf2Prf
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
          return resolve(false);
        } else {
          return resolve(true);
        }
      });
    });
  }
}
