'use strict';
import { expect } from 'chai';
import { join } from 'path';
import sinon from 'sinon';
import { ConfigHelper as Configure } from '../src/config/configure';
import { Mailer } from '../src/mailer';

const mailerTestConfig = new Configure({
  testMode: {
    noEmail: true
  },
  mailer: {
    fromEmail: 'noreply@example.com',
    retryOnError: {
      maxRetries: 3,
      initialBackoffSeconds: 0.1
    }
  },
  emailTemplates: {
    folder: join(__dirname, '../templates/email')
  }
});

const req = {
  protocol: 'https',
  headers: {
    host: 'example.com'
  }
};

const user = {
  name: 'Super',
  unverifiedEmail: {
    token: 'abc123'
  }
};

const mailer = new Mailer(mailerTestConfig.config);

describe('Mailer', function () {
  it('should send a confirmation email', function () {
    return mailer
      .sendEmail('confirmEmail', 'super@example.com', {
        req,
        user
      })
      .then(function (result) {
        const response = result.response.toString();
        expect(response.search('From: noreply@example.com')).to.be.greaterThan(
          -1
        );
        expect(response.search('To: super@example.com')).to.be.greaterThan(-1);
        expect(
          response.search('Subject: Please confirm your email')
        ).to.be.greaterThan(-1);
        expect(response.search('Hi Super,')).to.be.greaterThan(-1);
        expect(
          response.search('https://example.com/auth/confirm-email/abc123')
        ).to.be.greaterThan(-1);
      });
  });

  it('should render all default templates', async () => {
    const data = {
      req,
      user
    };
    let templateCount = 0;
    for (const template of Object.keys(
      mailerTestConfig.config.emailTemplates.templates
    )) {
      const res = await mailer.sendEmail(template, 'super@example.com', data);
      expect(
        res.response
          .toString()
          .search(`${new Date().getFullYear()} Fynn Leitow`)
      ).to.be.greaterThan(-1);

      templateCount += 1;
    }
    expect(templateCount).to.be.equal(6);
  });

  it('should retry 3x on error', async () => {
    mailer['transporter']['sendMail'] = x => {
      throw 'nope';
    };
    const spySendMail = sinon.spy(mailer['transporter'], 'sendMail');
    try {
      let res = await mailer.sendEmail('confirmEmail', 'super@example.com', {
        req,
        user
      });
    } catch (error) {
      expect(error).to.equal('nope');
    }
    expect(spySendMail.callCount).to.equal(4);
  });
});
