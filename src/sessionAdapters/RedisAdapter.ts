import { ConfigHelper } from '../config/configure';

import BPromise = require('bluebird');
import { SessionAdapter } from '../types/adapters';
const redis = BPromise.promisifyAll(require('redis'));

export class RedisAdapter implements SessionAdapter {
  #redisClient;

  constructor(config: ConfigHelper) {
    if (!config.getItem('session.redis.unix_socket')) {
      if (config.getItem('session.redis.url')) {
        this.#redisClient = redis.createClient(
          config.getItem('session.redis.url'),
          config.getItem('session.redis.options')
        );
      } else {
        this.#redisClient = redis.createClient(
          config.getItem('session.redis.port') || 6379,
          config.getItem('session.redis.host') || '127.0.0.1',
          config.getItem('session.redis.options')
        );
      }
    } else {
      this.#redisClient = redis.createClient(
        config.getItem('session.redis.unix_socket'),
        config.getItem('session.redis.options')
      );
    }

    // Authenticate with Redis if necessary
    if (config.getItem('session.redis.password')) {
      this.#redisClient
        .authAsync(config.getItem('session.redis.password'))
        .catch(err => {
          throw new Error(err);
        });
    }

    this.#redisClient.on('error', err => {
      console.error('Redis error: ' + err);
    });

    this.#redisClient.on('connect', () => {
      console.log('Redis is ready');
    });
  }
  storeKey(key: string, life: number, data: string) {
    return this.#redisClient.psetexAsync(key, life, data);
  }

  deleteKeys(keys: string[]) {
    return this.#redisClient.delAsync(keys);
  }

  getKey(key: string) {
    return this.#redisClient.getAsync(key);
  }

  quit() {
    return this.#redisClient.quit();
  }
}
