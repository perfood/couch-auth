import { SessionAdapter } from '../types/adapters';

export class MemoryAdapter implements SessionAdapter {
  #keys: Record<string, string>;
  #expires: Record<string, number>;
  constructor(config?: any) {
    this.#keys = {};
    this.#expires = {};
    console.log('Memory Adapter loaded');
  }

  storeKey(key: string, life: number, data: string) {
    const now = Date.now();
    this.#keys[key] = data;
    this.#expires[key] = now + life;
    this.removeExpired();
    return Promise.resolve();
  }

  getKey(key: string) {
    const now = Date.now();
    if (this.#keys[key] && this.#expires[key] > now) {
      return Promise.resolve(this.#keys[key]);
    } else {
      return Promise.resolve(false);
    }
  }

  deleteKeys(keys: string[]) {
    if (!(keys instanceof Array)) {
      keys = [keys];
    }
    keys.forEach(key => {
      delete this.#keys[key];
      delete this.#expires[key];
    });
    this.removeExpired();
    return Promise.resolve(keys.length);
  }

  quit() {
    return Promise.resolve();
  }

  private removeExpired() {
    const now = Date.now();
    Object.keys(this.#expires).forEach(key => {
      if (this.#expires[key] < now) {
        delete this.#keys[key];
        delete this.#expires[key];
      }
    });
  }
}
