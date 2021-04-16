import { Config } from '../types/config';
export declare class ConfigHelper {
    config: Config;
    constructor(data?: Partial<Config>);
    /** Verifies the config against some incompatible settings */
    private verifyConfig;
}
