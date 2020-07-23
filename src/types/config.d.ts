export interface TestConfig {
  /** Use a stub transport so no email is actually sent. Default: false */
  noEmail: boolean;
  /** Displays debug information in the oauth dialogs. Default: false */
  oauthDebug: boolean;
  /** Logs out-going emails to the console. Default: false */
  debugEmail: boolean;
}

export interface SecurityConfig {
  /** Roles given to a new user. Default: ['user'] */
  defaultRoles: string[];
  /** Disables the ability to link additional providers to an account when set to true */
  disableLinkAccounts: boolean;
  // Maximum number of failed logins before the account is locked
  maxFailedLogins: number;
  // The amount of time the account will be locked for (in seconds) after the maximum failed logins is exceeded
  lockoutTime: number;
  // The amount of time a new session is valid for (default: 24 hours)
  sessionLife: number;
  // The amount of time a password reset token is valid for
  tokenLife: number;
  // The maximum number of entries in the activity log in each user doc. Zero to disable completely
  userActivityLogSize: 10;
  // If set to true, the user will be logged in automatically after registering
  loginOnRegistration: boolean;
  // If set to true, the user will be logged in automatically after resetting the password
  loginOnPasswordReset: boolean;
}

export interface LengthConstraint {
  minimum: number;
  message: string;
}

export interface PasswordConstraints {
  length: LengthConstraint;
  matches: string;
}

export interface LocalConfig {
  // Send out a confirm email after each user signs up with local login
  sendConfirmEmail: boolean;
  // Require the email be confirmed before the user can login  or before his changed email is updated
  requireEmailConfirm: boolean;
  // Requires the correct `password` to be sent in the body in order to change the email
  requirePasswordOnEmailChange: boolean;
  // send a confirmation E-Mail to the user after the password has successfully been changed or resetted
  sendPasswordChangedEmail: boolean;
  // If this is set, the user will be redirected to this location after confirming email instead of JSON response
  confirmEmailRedirectURL: string;
  // Set this to true to disable usernames and use emails instead
  emailUsername: boolean;
  // Also return the username and UUID when creating a session
  sendNameAndUUID: boolean;
  // If a number is set here, the token for password reset will be shortened to that length (e.g. 8)
  tokenLengthOnReset: boolean | number;
  // Custom names for the username and password fields in your sign-in form
  usernameField: string;
  passwordField: string;
  // override default constraints (processed by sofa-model)
  passwordConstraints: PasswordConstraints;
}

export interface DBServerConfig {
  // The CouchDB compatible server where all your databases are stored on
  protocol: 'https://' | 'http://';
  host: string;
  user: string;
  password: string;
  // If the public uses a separate URL from your Node.js server to access the database specify it here.
  // This will be the access URL for all your user's personalDBs
  publicURL?: string;
  /**
   * Set this to `true` if you are using Cloudant with API-v2-keys and Cloudant's role system.
   * Provide `CLOUDANT_USER` and - unless you're using IAM for authentication - `CLOUDANT_PASS` as environment variables
   */
  cloudant?: boolean;
  /** Use this flag instead if you use Cloudant, but with the
   *  `_users` - DB and CouchDB's permission system instead */
  couchAuthOnCloudant?: boolean;
  /**
   * If specified together with `cloudant` or `couchAuthOnCloudant`, this IAM api key will be used for authentication
   * instead of legacy basic auth via `user:password`. Do not provide `password` or `CLOUDANT_PASS` if using IAM!
   */
  iamApiKey?: string;
  /** The name for the database that stores all your user information. This is distinct from CouchDB's _user database.
   * Alternatively you can pass in a `nano` instance to the SuperLogin constructor and leave this blank */
  userDB: string;
  /** CouchDB's _users database. Each session generates the user a unique login and password.
   * This is not used when `cloudant` is true, but can be used with
   * `couchStyleAuth` on Cloudant as well. */
  couchAuthDB: string;
}

export interface RedisConfig {
  // If url is supplied, port and host will be ignored
  url: string;
  port: number;
  host: string;
  // If a UNIX domain socket is specified, port, host and url will be ignored
  unix_socket: string;
  options: any;
  password: string;
}

export interface SessionConfig {
  adapter: 'memory' | 'redis' | 'file';
  /**
   * check CouchDB when a session is not present in the adapter. Should only be used for local development or if
   * redis was down. Cannot be used with Cloudant. Default: false
   */
  dbFallback?: boolean;
  file?: {
    sessionsRoot: string;
  };
  redis?: RedisConfig;
}

export interface EmailTemplate {
  subject: string;
  template?: string;
  format?: string;
  templates?: string[];
  formats?: string[];
}

export interface MailOptions {
  host?: string;
  port?: string;
  secure?: boolean;
  auth: {
    api_user?: string;
    api_key?: string;
    user?: string;
    pass?: string;
  };
}

export interface MailerConfig {
  // Email address that all your system emails will be from
  fromEmail: string;
  // Use this if you want to specify a custom Nodemailer transport. Defaults to SMTP or sendmail.
  transport?: any;
  // The options object that will be passed into your transport. These should usually be your SMTP settings.
  // If this is left blank, it will default to sendmail.
  options: MailOptions;
}

export interface TemplateConfig {
  // Customize the templates for the emails that SuperLogin sends out
  confirmEmail: EmailTemplate;
  confirmEmailChange?: EmailTemplate;
  forgotPassword: EmailTemplate;
  modifiedPassword: EmailTemplate;
}

export interface DefaultDBConfig {
  // Private databases are personal to each user. They will be prefixed with your setting below and postfixed with $USERNAME.
  private: string[];
  // Shared databases that you want the user to be authorized to use. These will not be prefixed, so type the exact name.
  shared: string[];
}

export interface SecurityRoles {
  admins: string[];
  members: string[];
}

export interface PersonalDBSettings {
  /** Array containing name of the design doc files (omitting .js extension), in the directory configured below */
  designDocs: string[];
  /** these permissions only work with the Cloudant API */
  permissions: string[];
  /** defaults to 'private' */
  type?: 'private' | 'shared';
  /** admin roles that will be automatically added to the db's _security object of this specific db. Default: [] */
  adminRoles?: string[];
  /** member roles that will be automatically added to the db's _security object of this specific db. Default: [] */
  memberRoles?: string[];
}

export interface PersonalDBModel {
  /** If `_default` is specified but your database is not listed below, these default settings will be applied */
  _default: PersonalDBSettings;
  /** Add specific settings for your dbs here */
  [db: string]: PersonalDBSettings;
}

export interface UserDBConfig {
  // These databases will be set up automatically for each new user
  defaultDBs: DefaultDBConfig;
  // If you specify default roles here (and use CouchDB not Cloudant) then these will be added to the _security object
  // of each new user database created. This is useful for preventing anonymous access.
  defaultSecurityRoles: SecurityRoles;
  // These are settings for each personal database
  model: PersonalDBModel;
  // Your private user databases will be prefixed with this:
  privatePrefix: string;
  // Directory that contains all your design docs
  designDocDir: string;
}

export interface ProviderCredentials {
  // Anything under credentials will be passed in to passport.use
  // It is a best practice to put any sensitive credentials in environment variables rather than your code
  clientID: string;
  clientSecret: string;
  [key: string]: any;
}

export interface ProviderOptions {
  // Anything under options will be passed in with passport.authenticate
  scope: string[];
  [key: string]: any;
}

export interface ProviderConfig {
  // Supply your app's credentials here. The callback url is generated automatically.
  // See the Passport documentation for your specific strategy for details.
  credentials: ProviderCredentials;
  // Any additional options you want to supply your authentication strategy such as requested permissions
  options: ProviderOptions;
  // This will pass in the user's auth token as a variable called 'state' when linking to this provider
  // Defaults to true for Google and LinkedIn, but you can enable it for other providers if needed
  stateRequired: boolean;
}

export interface Config {
  testMode: TestConfig;
  security: SecurityConfig;
  local: LocalConfig;
  session: SessionConfig;
  dbServer: DBServerConfig;
  emails: TemplateConfig;
  // Custom settings to manage personal databases for your users
  userDBs: UserDBConfig;
  providers: { [provider: string]: ProviderConfig };
}
