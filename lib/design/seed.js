"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
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
            }
            else if (type === 'function') {
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
    if (!remote)
        return false;
    return deepEqual(local, remote, { strict: true });
}
function seed(db, design, cb) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!db || !design) {
            throw new TypeError('`db` and `design` are required');
        }
        const local = objmap(objkeysmap(design, addDesign), normalizeDoc);
        try {
            const docs = yield db.list({
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
                if (!remote[key])
                    return true;
                local[key]._rev = remote[key]._rev;
                return !docEqual(local[key], remote[key]);
            })
                .map(key => {
                return local[key];
            });
            let result = false;
            if (update.length > 0) {
                result = yield db.bulk({ docs: update });
            }
            if (typeof cb === 'function') {
                cb(null, result);
            }
            return result;
        }
        catch (err) {
            if (typeof cb === 'function') {
                cb(err, null);
            }
            console.log(err);
            return Promise.reject(err);
        }
    });
}
exports.default = seed;
