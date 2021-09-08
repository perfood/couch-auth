'use strict';
import { Config } from '../types/config.model';
import { defaultConfig } from './default.config';
import { mergeConfig } from '../util';

export class ConfigHelper {
  public config: Config = defaultConfig;

  constructor(data: Partial<Config> = {}) {
    // Some extra default settings if no config object is specified
    if (Object.keys(data).length === 0) {
      this.config.testMode = {
        noEmail: true,
        debugEmail: true
      };
    } else {
      this.config = mergeConfig(this.config, data);
      this.verifyConfig();
    }
  }

  /** Verifies the config against some incompatible settings */
  private verifyConfig() {
    if (
      this.config.dbServer?.iamApiKey &&
      (this.config.dbServer?.password || process.env.CLOUDANT_PASS)
    ) {
      throw 'do not provide a password when using IAM authentication!';
    }
    if (
      this.config.local?.requireEmailConfirm &&
      !this.config.local.sendConfirmEmail
    ) {
      throw 'sendConfirmEmail must also be set if requireEmailConfirm is.';
    }
    if (this.config.security?.iterations) {
      const itArr = this.config.security.iterations;
      let prev = 0;
      for (const pair of itArr) {
        if (
          pair.length !== 2 ||
          typeof pair[0] !== 'number' ||
          typeof pair[1] !== 'number' ||
          pair[0] < prev
        ) {
          throw 'iterations are specified but have invalid format!';
        }
        prev = pair[0];
      }
    }
  }
}
