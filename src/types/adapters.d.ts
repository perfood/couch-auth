import { DocumentScope } from 'nano';

export interface DBAdapter {
  storeKey: Function;
  removeKeys: Function;
  initSecurity: Function;
  retrieveKey: Function;
  authorizeKeys: (
    user_id: string,
    db: DocumentScope<any>,
    keys: Record<string, any> | Array<string> | string,
    permissions?: string[],
    roles?: string[]
  ) => Promise<any>;
  deauthorizeKeys: (
    db: DocumentScope<any>,
    keys: string[] | string
  ) => Promise<any>;
}

export interface SessionAdapter {
  storeKey: (key: string, life: number, data: string) => Promise<any>;
  deleteKeys: (keys: string[]) => Promise<any>;
  getKey: (key: string) => Promise<any>;
  quit: Function;
}
