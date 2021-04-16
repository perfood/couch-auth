'use strict';
import { defaultConfig } from './default.config';
import { mergeConfig } from '../util';
export class ConfigHelper {
    constructor(data = {}) {
        this.config = defaultConfig;
        // Some extra default settings if no config object is specified
        if (Object.keys(data).length === 0) {
            this.config.testMode = {
                noEmail: true,
                debugEmail: true
            };
        }
        else {
            this.config = mergeConfig(this.config, data);
            this.verifyConfig();
        }
    }
    /** Verifies the config against some incompatible settings */
    verifyConfig() {
        var _a, _b, _c, _d;
        if (((_a = this.config.dbServer) === null || _a === void 0 ? void 0 : _a.iamApiKey) &&
            (((_b = this.config.dbServer) === null || _b === void 0 ? void 0 : _b.password) || process.env.CLOUDANT_PASS)) {
            throw 'do not provide a password when using IAM authentication!';
        }
        if (((_c = this.config.local) === null || _c === void 0 ? void 0 : _c.requireEmailConfirm) &&
            !this.config.local.sendConfirmEmail) {
            throw 'sendConfirmEmail must also be set if requireEmailConfirm is.';
        }
        if ((_d = this.config.security) === null || _d === void 0 ? void 0 : _d.iterations) {
            const itArr = this.config.security.iterations;
            let prev = 0;
            for (const pair of itArr) {
                if (pair.length !== 2 ||
                    typeof pair[0] !== 'number' ||
                    typeof pair[1] !== 'number' ||
                    pair[0] < prev) {
                    throw 'iterations are specified but have invalid format!';
                }
                prev = pair[0];
            }
        }
    }
}
