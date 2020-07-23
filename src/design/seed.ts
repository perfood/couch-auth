/**
Copyright (C) 2013 by Maciej Małecki, portions (C) 2014-2016 by Colin Skow
and (C) 2020 by Fynn Leitow

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

import {
  DocumentInsertResponse,
  DocumentScope,
  IdentifiedDocument,
  MaybeIdentifiedDocument,
  MaybeRevisionedDocument
} from 'nano';

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
  return JSON.stringify(local) === JSON.stringify(remote);
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

    let result: DocumentInsertResponse[] | boolean = false;
    if (update.length > 0) {
      result = await db.bulk({ docs: update });
    }
    return result;
  } catch (err) {
    return Promise.reject(err);
  }
}
