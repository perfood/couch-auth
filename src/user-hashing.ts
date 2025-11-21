import pwdModule from '@sl-nx/couch-pwd';
import { Config } from './types/config';
import { HashResult } from './types/typings';
import { UserHashingLegacy } from './user-hashing-legacy';

/**
 * Class for hashing and verifying sl-user passwords
 */
export class UserHashing {
  private legacy: UserHashingLegacy;

  private pwdCouch: pwdModule;
  private iterations: number;
  private pbkdf2Prf: string;
  private keyLength: number;
  private saltLength: number;

  constructor(config: Partial<Config>) {
    this.legacy = new UserHashingLegacy(config);
    this.iterations = config.security?.userHashing?.iterations || 600000;
    this.pbkdf2Prf = config.security?.userHashing?.pbkdf2Prf || 'sha256';
    this.keyLength = config.security?.userHashing?.keyLength || (this.pbkdf2Prf === 'sha' ? 20 : 32);
    this.saltLength = config.security?.userHashing?.saltLength || 16;

    this.pwdCouch = UserHashing.createPwdModule(
      this.iterations,
      this.keyLength,
      this.saltLength,
      this.pbkdf2Prf
    );
  }

  isUpgradeNeeded(hashObj: HashResult): boolean {
    if (hashObj.iterations === undefined) {
      return true;
    }
    if (hashObj.iterations < this.iterations) {
      return true;
    }
    if ((hashObj.pbkdf2_prf || 'sha') !== this.pbkdf2Prf) {
      return true;
    }
    return false;
  }

  hashUserPassword(password: string): Promise<HashResult> {
    return new Promise((resolve, reject) => {
      this.pwdCouch.hash(password, (err, salt, hash) => {
        if (err) {
          return reject(err);
        }
        return resolve({
          created: Date.now(),
          salt: salt,
          derived_key: hash,
          password_scheme: 'pbkdf2',
          pbkdf2_prf: this.pbkdf2Prf,
          iterations: this.iterations
        });
      });
    });
  }

  verifyUserPassword(hashObj: HashResult, pw: string): Promise<boolean> {
    if (hashObj.iterations === undefined) {
      return this.legacy.verifyUserPassword(hashObj, pw);
    }

    return new Promise((resolve, reject) => {
      const iterations = hashObj.iterations || 10;
      const digest = hashObj.pbkdf2_prf || 'sha';
      const length = digest === 'sha' ? 20 : 32;
      const pwdCouch = UserHashing.createPwdModule(iterations, length, 16, digest);
      
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
