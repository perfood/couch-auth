import {
  Document,
  DocumentScope as NanoDocumentScope,
  ServerScope as NanoServerScope,
  IdentifiedDocument,
  MaybeRevisionedDocument
} from 'nano';
import {
  DocumentScope as CloudantDocumentScope,
  ServerScope as CloudantServerScope
} from '@cloudant/cloudant';
import { Request } from 'express';

export type ServerScope = NanoServerScope | CloudantServerScope;
export type DocumentScope<D> = NanoDocumentScope<D> | CloudantDocumentScope<D>;

export interface IdentifiedObj {
  name: string;
  type: string;
}

export interface CouchDbAuthDoc
  extends IdentifiedDocument,
    MaybeRevisionedDocument,
    IdentifiedObj {
  user_id: string;
  password?: string;
  expires: number;
  roles: string[];
  provider: string;
  password_scheme?: string;
  iterations?: number;
  derived_key?: string;
  salt?: string;
}

export interface HashResult {
  salt?: string;
  derived_key?: string;
  /**
   * timestamp of the creation of this HashResult. If `undefined`, the default
   * iteration number (10) is used, else the value specified in the config
   * (`security.iterations`) that matches the creation date.
   */
  created?: number;
}

export interface LocalHashObj extends HashResult {
  /** @deprecated */
  failedLoginAttempts?: number;
  iterations?: number;
  /** @deprecated */
  lockedUntil?: number;
}

export interface SignUpObj {
  provider: string;
  timestamp: string;
}

export interface PersonalDBCollection {
  [dbName: string]: IdentifiedObj;
}

export interface TimeRestricted {
  issued: number;
  expires: number;
}

export interface SessionObj extends TimeRestricted {
  provider: string;
}

export interface SessionCollection {
  [session: string]: SessionObj;
}

export interface PasswortResetEntry extends TimeRestricted {
  token: string;
}

export interface SlUserDoc extends Document, IdentifiedObj {
  /** todo: remove this, it's confusing. */
  user_uid?: string;
  /** this is the `_id` in version 1 of superlogin - for login with username */
  key: string;
  roles: string[];
  providers: string[];
  local: LocalHashObj;
  forgotPassword?: PasswortResetEntry;
  unverifiedEmail?: { email: string; token: string };
  signUp: SignUpObj;
  personalDBs: PersonalDBCollection;
  email: string;
  session: SessionCollection;
  profile: any;
}

export interface SlUserNew extends SlUserDoc {
  password?: string;
  confirmPassword?: string;
}

export interface SlRefreshSession extends TimeRestricted {
  provider: string;
  roles: string[];
  token: string;
  /** This will still be the old `_id`, i.e. `key` now */
  user_id: string;
  /** unique identifier of the user's DB, `including` the hyphens. */
  user_uid: string;
}

export interface SlLoginSession extends SlRefreshSession {
  password: string;
  userDBs: { [db: string]: string };
  profile?: string;
  /** Name for Display purposes only */
  name?: string;
}

export interface SlUser {
  provider?: string;
  _id?: string;
  key?: string;
  roles?: string[];
  user_id?: string;
}

export interface SlRequest extends Request {
  user: SlUser;
}
