import { ConfigHelper } from '../config/configure';
import { SessionAdapter } from '../types/adapters';

const fs = require('fs-extra');
const path = require('path');

export class FileAdapter implements SessionAdapter {
  #sessionFolder;
  constructor(config: ConfigHelper) {
    const sessionsRoot = config.getItem('session.file.sessionsRoot');
    this.#sessionFolder = path.join(process.env.PWD, sessionsRoot);
    console.log('File Adapter loaded');
  }

  private getFilepath(key: string) {
    return path.format({
      dir: this.#sessionFolder,
      base: key + '.json'
    });
  }

  storeKey(key: string, life: number, data: string) {
    const now = Date.now();
    return fs.outputJson(this.getFilepath(key), {
      data: data,
      expire: now + life
    });
  }

  getKey(key: string) {
    const now = Date.now();
    return fs
      .readJson(this.getFilepath(key))
      .then(session => {
        if (session.expire > now) {
          return session.data;
        }
        return false;
      })
      .catch(() => {
        return false;
      });
  }

  deleteKeys(keys: string[]) {
    if (!(keys instanceof Array)) {
      keys = [keys];
    }
    const deleteQueue = keys.map(key => {
      return fs.remove(this.getFilepath(key));
    });

    return Promise.all(deleteQueue).then(done => {
      // this._removeExpired(); todo maybe?
      return done.length;
    });
  }

  quit() {
    return Promise.resolve();
  }
}
