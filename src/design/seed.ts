import {
  DocumentBulkResponse,
  DocumentScope,
  IdentifiedDocument,
  RevisionedDocument
} from 'nano';

const objmap = require('object-map');
const objkeysmap = require('object-keys-map');
const deepEqual = require('deep-equal');

function addDesign(s) {
  return '_design/' + s;
}

function normalizeDoc(
  doc: IdentifiedDocument & RevisionedDocument,
  id: string
) {
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

export default async function seed(
  db: DocumentScope<any>,
  design: any,
  cb?: Function
) {
  if (!db || !design) {
    throw new TypeError('`db` and `design` are required');
  }
  const local = objmap(objkeysmap(design, addDesign), normalizeDoc);
  try {
    const docs = await db.list({
      include_docs: true,
      keys: Object.keys(local)
    });
    const remote = {};

    docs.rows.forEach(doc => {
      if (doc.doc) {
        remote[doc.key] = doc.doc;
      }
    });

    const update = Object.keys(local)
      .filter(key => {
        if (!remote[key]) return true;
        local[key]._rev = remote[key]._rev;
        return !docEqual(local[key], remote[key]);
      })
      .map(key => {
        return local[key];
      });

    let result: DocumentBulkResponse[] | boolean = false;
    if (update.length > 0) {
      result = await db.bulk({ docs: update });
    }
    if (typeof cb === 'function') {
      cb(null, result);
    }
    return result;
  } catch (err) {
    if (typeof cb === 'function') {
      cb(err, null);
    }
    console.log(err);
    return Promise.reject(err);
  }
}
