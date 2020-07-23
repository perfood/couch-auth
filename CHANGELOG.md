## Change Log

#### Cloudant IAM (0.13)

Use Cloudant Library for compatibility with IAM auth instead of `user:password` (downgraded nano)

- Added 2x retry when working with cloudant
- Using CookieAuth if `cloudant` is true and not IAM

#### Bugfix forgot-password (0.12.1)

Reject early if no valid email was provided with the request

#### Error Handling (0.12.0)

Only send errors as response that are meant to be user-facing

- Otherwise, just send a generic error
- Adjusted the logging accordingly (warn/error level)

#### TypeScript improvements, Dependency cleanup (0.11.0)

**Breaking**
Compile target is now ES2019, requiring NodeJS 12 or above.

#### Refactoring to TypeScript and Nano (0.10.0)

**Breaking**
Replaced PouchDB with Nano. A PouchDB can no longer be passed to SuperLogin. a Nano-DB can be used instead.

- Made deauthorization behaviour more robust against network failures. `logout` now also resolves if access token has only been removed from `_user`.
- Cloudant and Oauth should work as expected now. Let me know if it does.
- More modules refactored to classes, moved refactored `pouchdb-seed-design` inside this project.

#### Adjusted Email handling (0.9.0)

- If password is reset, email will be marked as confirmed and `"'verified via password reset'"` will be logged.
- new config options:
  - `local.requirePasswordOnEmailChange`: If true, the correct `password` is needed in the request body in order to change the email.
  - `email.confirmEmailChange`: If set, this template is used when requesting an email change and `local.confirmEmail` is active.
  - `/change-email` now responds with `"email change requested"` if the email needs to be confirmed

#### Refactoring, notify on password change, CouchDB as Fallback (0.8.0)

- eslint/prettier for code linting/formatting
- refactored Mailer and User into classes
- provider is now also stored in the doc in CouchDB's `_user` - DB
- new config options:
  - `local.sendPasswordChangedEmail`: if true, send a notification email when password is changed
  - `session.dbFallback`: if true, CouchDB will be checked as a fallback if the adapter does not have that session stored
- Travis CI to Node 12, Node 10 no longer supported due to private fields

#### Updates and Adjustments: SuperloginX (0.7.1)

- Removal of Bluebird in favour of native Promises
- Adjustment of Travis CI for NodeJS 10 with ES6
- Updating all packages to more secure versions
- not allowing `_` as prefix for userDBs
- Updated E-Mail Regex
- Added two custom options to config (shorter PW-reset token, sending UUID with session info)

#### Misc. Bug Fixes (0.6.1) 2016-04-02

- Misc bugfixes
- Documentation improvements
- Now testing against Node 4.x and 5.x

##### Improved Tests, Enhancements, Bugfixes (0.6.0) 2016-04-02

- Updated dependencies
- Improved unit tests (thanks [@tohagan](https://github.com/tohagan) and [@ybian](https://github.com/ybian))
- CouchDB server can now have a separate URL for public access
- Misc bug fixes

##### Enable Logout of Expired Sessions (0.5.0) 2015-10-08

Previously a user could only logout if the session token was still valid. API keys would be expired, but database credentials could still be used. Now logout will ensure the user is completely logged out, even if the session is already expired. Also fixed a bug that was causing `sessionLife` and `tokenLife` settings not to work.

##### Custom Permissions for Cloudant (0.4.0) 2015-09-21

Default per-DB Cloudant permissions no longer save in the user doc. You can set custom permissions in the user doc, otherwise it will use the settings in your config. Misc bug fixes.

##### Security Roles For CouchDB (0.3.0) 2015-09-18

Created configuration options to setup \_security roles when user databases are created. Improved tests and updated PouchDB.

##### Client Access Token Strategies (0.2.0) 2015-09-13

Added client `access_token` strategies to support OAuth2 flows from Cordova, PhoneGap, and native apps.

##### Initial Release (0.1.0) 2015-09-10

The intense power of SuperLogin is unleashed on a world that may not be ready! Tested with Node.js 0.12.7 and 4.0.0.
