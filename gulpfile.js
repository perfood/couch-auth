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

function cloudant_test() {
  return src(['test/cloudant.spec.ts'], { read: false }).pipe(mocha());
}

// these three tasks all just need dbauth
function session_test() {
  return src(['test/session.spec.ts'], { read: false }).pipe(mocha());
}

function mailer_test() {
  return src(['test/mailer.spec.ts'], { read: false }).pipe(mocha());
}

function user_test() {
  return src(['test/user.spec.ts'], { read: false }).pipe(mocha());
}

// depends on user-test. todo: fix exports and move to ts
function final_test() {
  return src(['test/test.spec.ts'], { read: false }).pipe(
    mocha({ timeout: 5000 })
  );
}

let tasks = [lint, middleware_test, dbauth_test];
if (!process.env.CLOUDANT_USER || !process.env.CLOUDANT_PASS) {
  console.warn('No credentials provided, skipping Cloudant test');
} else {
  tasks.push(cloudant_test);
}
tasks = tasks.concat([session_test, mailer_test, user_test, final_test]);
exports.default = series(tasks);
