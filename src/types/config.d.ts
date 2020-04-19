export interface DBServerConfig {
  protocol: string;
  host: string;
  user: string;
  password: string;
  publicURL?: string;
  cloudant?: boolean;
  userDB: string;
  couchAuthDB: string;
}

export interface Config {
  [key: string]: any;
}
