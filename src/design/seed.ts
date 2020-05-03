import {
  DocumentBulkResponse,
  DocumentScope,
  IdentifiedDocument,
  MaybeIdentifiedDocument,
  MaybeRevisionedDocument
} from 'nano';
import deepEqual from 'deep-equal';

function addDesign(s) {
  return '_design/' + s;
}

/**
 * normalizes the document into the JSON format it has
 * in the CouchDB, converting functions into strings and
 * specify
 */
function normalizeDoc(
  doc: MaybeIdentifiedDocument & MaybeRevisionedDocument,
  id: string
): IdentifiedDocument {
  function normalize(doc) {
    doc = Object.assign({}, doc);
    for (const [prop, entry] of Object.entries(doc)) {
      const type = typeof entry;
      if (type === 'object') {
        doc[prop] = normalize(entry);
      } else if (type === 'function') {
        doc[prop] = entry.toString();
      }
    }
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

export default async function seed(db: DocumentScope<any>, design: any) {
  if (!db || !design) {
    throw new TypeError('`db` and `design` are required');
  }
  const local = {};
  for (const [id, data] of Object.entries(design)) {
    const ddocId = addDesign(id);
    local[ddocId] = normalizeDoc(data, ddocId);
  }
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
    return result;
  } catch (err) {
    return Promise.reject(err);
  }
}
