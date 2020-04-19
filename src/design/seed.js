const objmap = require('object-map');
const objkeysmap = require('object-keys-map');
const deepEqual = require('deep-equal');

function addDesign(s) {
  return '_design/' + s;
}

function normalizeDoc(doc, id) {
  function normalize(doc) {
    doc = Object.assign({}, doc);
    Object.keys(doc).forEach(function (prop) {
      const type = typeof doc[prop];
      if (type === 'object') {
        doc[prop] = normalize(doc[prop]);
      } else if (type === 'function') {
        doc[prop] = doc[prop].toString();
      }
    });
    return doc;
  }

  const output = normalize(doc);
  output._id = id || doc._id;
  output._rev = doc._rev;
  return output;
}

function docEqual(local, remote) {
  if (!remote) return false;
  return deepEqual(local, remote, { strict: true });
}

/**
 *
 * @param {import('nano').DocumentScope} db
 * @param {*} design
 * @param {Function=} cb
 */
export default function seed(db, design, cb) {
  if (!db || !design) {
    throw new TypeError('`db` and `design` are required');
  }

  const local = objmap(objkeysmap(design, addDesign), normalizeDoc);

  const seedPromise = db
    .list({ include_docs: true, keys: Object.keys(local) })
    .then(function (docs) {
      const remote = {};

      docs.rows.forEach(function (doc) {
        if (doc.doc) {
          remote[doc.key] = doc.doc;
        }
      });

      const update = Object.keys(local)
        .filter(function (key) {
          if (!remote[key]) return true;
          local[key]._rev = remote[key]._rev;
          return !docEqual(local[key], remote[key]);
        })
        .map(function (key) {
          return local[key];
        });

      if (update.length > 0) {
        return db.bulk({ docs: update });
      } else {
        return Promise.resolve(false);
      }
    })
    .then(function (result) {
      if (typeof cb === 'function') {
        cb(null, result);
      }
      return Promise.resolve(result);
    })
    .catch(function (err) {
      if (typeof cb === 'function') {
        cb(err, null);
      }
      console.log(err);
      return Promise.reject(err);
    });

  return seedPromise;
}
