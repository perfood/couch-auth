'use strict';
const express = require('express');
const http = require('http');
const bodyParser = require('body-parser');
const morgan = require('morgan');

const SuperLogin = require('../lib/index');

function start(config) {
  const app = express();

  // all environments
  app.set('port', process.env.PORT || config.port || 5000);
  app.use(morgan('dev'));
  app.use(bodyParser.json());

  // Initialize SuperLogin
  let superlogin;
  try {
    superlogin = new SuperLogin(config);
  } catch (error) {
    console.warn('error creating SuperLogin: ', error);
  }
  // Mount SuperLogin's routes to our app
  app.use('/auth', superlogin.router);

  app.get(
    '/user',
    superlogin.requireAuth,
    superlogin.requireRole('user'),
    function (req, res) {
      res.send('role user');
    }
  );

  app.get(
    '/admin',
    superlogin.requireAuth,
    superlogin.requireRole('admin'),
    function (req, res) {
      res.send('role admin');
    }
  );

  const server = http.createServer(app).listen(app.get('port'));

  app.shutdown = function () {
    superlogin.quitRedis();
    server.close();
  };

  app.config = superlogin.config;
  app.superlogin = superlogin;

  return app;
}

// export app for testing
if (require.main === module) {
  // called directly
  start(require('./test.config'));
} else {
  // required as a module -> from test file
  module.exports = function (config) {
    return start(config);
  };
}
