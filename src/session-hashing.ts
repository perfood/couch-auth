'use strict';
import pwdModule from '@sl-nx/couch-pwd';
import { Config } from './types/config';
import { HashResult } from './types/typings';

export class SessionHashing {

  static invalidErr = { status: 401, message: 'invalid token' };

  // Hasher for hashing _users passwords
  private pwdCouch: pwdModule;
  private iterations: number;
  private pbkdf2Prf: string;
  private keyLength: number;
  private saltLength: number;
  
  constructor(config: Partial<Config>) {
    this.iterations = config.security?.sessionHashing?.iterations || 1000;
    this.pbkdf2Prf = config.security?.sessionHashing?.pbkdf2Prf || 'sha256';
    this.keyLength = config.security?.sessionHashing?.keyLength || (this.pbkdf2Prf === 'sha' ? 20 : 32);
    this.saltLength = config.security?.sessionHashing?.saltLength || 16;

    this.pwdCouch = SessionHashing.createPwdModule(
      this.iterations,
      this.keyLength,
      this.saltLength,
      this.pbkdf2Prf
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
          pbkdf2_prf: this.pbkdf2Prf,
          iterations: this.iterations
        });
      });
    });
  }
  
  public verifySessionPassword(hashObj: HashResult, pw: string): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const iterations = hashObj.iterations || 10;
      const digest = hashObj.pbkdf2_prf || 'sha';
      const length = digest === 'sha' ? 20 : 32;
      const pwdCouch = SessionHashing.createPwdModule(iterations, length, 16, digest);
      
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

  private static createPwdModule(iterations: number, keyLength: number, saltLength: number, digest: string): pwdModule {
    return new pwdModule(
      iterations,
      keyLength,
      saltLength,
      'hex',
      digest === 'sha' ? 'sha1' : digest
    );
  }
}
