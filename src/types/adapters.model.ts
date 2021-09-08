import { DocumentScope } from 'nano';

// @internal
export interface DBAdapter {
  storeKey: Function;
  removeKeys: Function;
  initSecurity: Function;
  retrieveKey: Function;
  extendKey: (string, number) => Promise<any>;
  authorizeKeys: (
    db: DocumentScope<any>,
    keys: Record<string, any> | Array<string> | string
  ) => Promise<any>;
  deauthorizeKeys: (
    db: DocumentScope<any>,
    keys: string[] | string
  ) => Promise<any>;
}

// @internal
export interface SessionAdapter {
  storeKey: (key: string, life: number, data: string) => Promise<any>;
  deleteKeys: (keys: string[]) => Promise<any>;
  getKey: (key: string) => Promise<any>;
  quit: Function;
}
