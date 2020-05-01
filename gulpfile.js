const { src, series } = require('gulp');
const eslint = require('gulp-eslint');
const mocha = require('gulp-mocha');

console.log('running tests from working directory: ', __dirname);

function lint() {
  return src(['./lib/**/*.js', './test/*.js'])
    .pipe(eslint({ node: true, mocha: true }))
    .pipe(eslint.format())
    .pipe(eslint.failAfterError());
}

function middleware_test() {
  return src(['test/middleware.spec.js'], { read: false }).pipe(
    mocha({ timeout: 2000 })
  );
}

function dbauth_test() {
  return src(['test/dbauth.spec.js'], { read: false }).pipe(
    mocha({ timeout: 2000 })
  );
}

function cloudant_test() {
  return src(['test/cloudant.spec.js'], { read: false }).pipe(
    mocha({ timeout: 2000 })
  );
}

// these three tasks all just need dbauth
function session_test() {
  return src(['test/session.spec.js'], { read: false }).pipe(
    mocha({ timeout: 2000 })
  );
}

function mailer_test() {
  return src(['test/mailer.spec.js'], { read: false }).pipe(
    mocha({ timeout: 2000 })
  );
}

function user_test() {
  return src(['test/user.spec.js'], { read: false }).pipe(
    mocha({ timeout: 2000 })
  );
}

// depends on user-test
function final_test() {
  return src(['test/test.js'], { read: false }).pipe(mocha({ timeout: 2000 }));
}

let tasks = [lint, middleware_test, dbauth_test];
if (!process.env.CLOUDANT_USER || !process.env.CLOUDANT_PASS) {
  console.warn('No credentials provided, skipping Cloudant test');
} else {
  tasks.push(cloudant_test);
}
tasks = tasks.concat([session_test, mailer_test, user_test, final_test]);
exports.default = series(tasks);
