'use strict';
var fs = require('fs');
var nodemailer = require('nodemailer');
var ejs = require('ejs');

class Mailer {
  constructor(config) {
    // Initialize the transport mechanism with nodermailer
    this.config = config;
    var customTransport = config.getItem('mailer.transport');
    if (config.getItem('testMode.noEmail')) {
      this.transporter = nodemailer.createTransport(
        require('nodemailer-stub-transport')()
      );
    } else if (customTransport) {
      this.transporter = nodemailer.createTransport(
        customTransport(config.getItem('mailer.options'))
      );
    } else {
      this.transporter = nodemailer.createTransport(
        config.getItem('mailer.options')
      );
    }
  }

  sendEmail(templateName, email, locals) {
    // load the template and parse it
    var templateFile = this.config.getItem(
      'emails.' + templateName + '.template'
    );
    if (!templateFile) {
      return Promise.reject('No template found for "' + templateName + '".');
    }
    var template = fs.readFileSync(templateFile, 'utf8');
    if (!template) {
      return Promise.reject('Failed to locate template file: ' + templateFile);
    }
    var body = ejs.render(template, locals);
    // form the email
    var subject = this.config.getItem('emails.' + templateName + '.subject');
    var format = this.config.getItem('emails.' + templateName + '.format');
    var mailOptions = {
      from: this.config.getItem('mailer.fromEmail'),
      to: email,
      subject: subject
    };
    if (format === 'html') {
      mailOptions.html = body;
    } else {
      mailOptions.text = body;
    }
    if (this.config.getItem('testMode.debugEmail')) {
      console.log(mailOptions);
    }
    // send the message
    return this.transporter.sendMail(mailOptions);
  }
}
module.exports = Mailer;
