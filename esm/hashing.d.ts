import { HashResult, LocalHashObj } from './types/typings';
import { Config } from './types/config';
export declare function hashCouchPassword(password: string): Promise<HashResult>;
export declare class Hashing {
    hashers: any[];
    times: number[];
    constructor(config: Partial<Config>);
    private getHasherForTimestamp;
    hashUserPassword(pw: string): Promise<HashResult>;
    verifyUserPassword(hashObj: LocalHashObj, pw: string): Promise<boolean>;
}
