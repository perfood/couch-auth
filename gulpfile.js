const { src, series } = require('gulp');
const eslint = require('gulp-eslint');
const mocha = require('gulp-mocha');

console.log('running tests from working directory: ', __dirname);

function lint() {
  return src(['./src/**/*.ts', './test/*.ts'])
    .pipe(eslint({ node: true, mocha: true }))
    .pipe(eslint.format())
    .pipe(eslint.failAfterError());
}

function middleware_test() {
  return src(['test/middleware.spec.ts'], { read: false }).pipe(mocha());
}

function dbauth_test() {
  return src(['test/dbauth.spec.ts'], { read: false }).pipe(mocha());
}

function session_test() {
  return src(['test/session.spec.ts'], { read: false }).pipe(mocha());
}

function mailer_test() {
  return src(['test/mailer.spec.ts'], { read: false }).pipe(mocha());
}

function user_test() {
  return src(['test/user.spec.ts'], { read: false }).pipe(mocha());
}

function final_test() {
  return src(['test/test.spec.ts'], { read: false }).pipe(
    mocha({ timeout: 5000 })
  );
}

const tasks = [
  lint,
  middleware_test,
  dbauth_test,
  session_test,
  mailer_test,
  user_test,
  final_test
];
exports.default = series(tasks);
