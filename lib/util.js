'use strict';
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const urlsafe_base64_1 = __importDefault(require("urlsafe-base64"));
const uuid_1 = require("uuid");
const couch_pwd_1 = __importDefault(require("@sensu/couch-pwd"));
const crypto_1 = __importDefault(require("crypto"));
const util_1 = require("util");
const getHash = util_1.promisify(couch_pwd_1.default.hash);
function URLSafeUUID() {
    return urlsafe_base64_1.default.encode(uuid_1.v4(null, Buffer.alloc(16)));
}
exports.URLSafeUUID = URLSafeUUID;
function hashToken(token) {
    return crypto_1.default.createHash('sha256').update(token).digest('hex');
}
exports.hashToken = hashToken;
function hashPassword(password) {
    return new Promise((resolve, reject) => {
        couch_pwd_1.default.hash(password, (err, salt, hash) => {
            if (err) {
                return reject(err);
            }
            return resolve({
                salt: salt,
                derived_key: hash
            });
        });
    });
}
exports.hashPassword = hashPassword;
function verifyPassword(hashObj, password) {
    const iterations = hashObj.iterations;
    const salt = hashObj.salt;
    const derived_key = hashObj.derived_key;
    if (iterations) {
        couch_pwd_1.default.iterations(iterations);
    }
    if (!salt || !derived_key) {
        return Promise.reject(false);
    }
    return getHash(password, salt).then(hash => {
        if (hash === derived_key) {
            return Promise.resolve(true);
        }
        else {
            return Promise.reject(false);
        }
    });
}
exports.verifyPassword = verifyPassword;
function getCloudantURL() {
    return ('https://' +
        process.env.CLOUDANT_USER +
        ':' +
        process.env.CLOUDANT_PASS +
        '@' +
        process.env.CLOUDANT_USER +
        '.cloudantnosqldb.appdomain.cloud');
}
exports.getCloudantURL = getCloudantURL;
function getDBURL(db) {
    let url;
    if (db.user) {
        url =
            db.protocol +
                encodeURIComponent(db.user) +
                ':' +
                encodeURIComponent(db.password) +
                '@' +
                db.host;
    }
    else {
        url = db.protocol + db.host;
    }
    return url;
}
exports.getDBURL = getDBURL;
function getFullDBURL(dbConfig, dbName) {
    return exports.getDBURL(dbConfig) + '/' + dbName;
}
exports.getFullDBURL = getFullDBURL;
function toArray(obj) {
    if (!(obj instanceof Array)) {
        return [obj];
    }
    return obj;
}
exports.toArray = toArray;
/**
 * extracts the session keys from the SlUserDoc
 */
function getSessions(userDoc) {
    return userDoc.session ? Array.from(Object.keys(userDoc.session)) : [];
}
exports.getSessions = getSessions;
function getExpiredSessions(userDoc, now) {
    return userDoc.session
        ? Array.from(Object.keys(userDoc.session)).filter(s => userDoc.session[s].expires <= now)
        : [];
}
exports.getExpiredSessions = getExpiredSessions;
/**
 * Takes a req object and returns the bearer token, or undefined if it is not found
 */
function getSessionToken(req) {
    if (req.headers && req.headers.authorization) {
        const parts = req.headers.authorization.split(' ');
        if (parts.length == 2) {
            const scheme = parts[0];
            const credentials = parts[1];
            if (/^Bearer$/i.test(scheme)) {
                const parse = credentials.split(':');
                if (parse.length < 2) {
                    return;
                }
                return parse[0];
            }
        }
    }
}
exports.getSessionToken = getSessionToken;
/**
 * Generates views for each registered provider in the user design doc
 */
function addProvidersToDesignDoc(config, ddoc) {
    const providers = config.getItem('providers');
    if (!providers) {
        return ddoc;
    }
    Object.keys(providers).forEach(provider => {
        ddoc.auth.views[provider] = {
            map: `function(doc) {
            if(doc.${provider} && doc.${provider}.profile){
                emit(doc.${provider}.profile.id, null);
            }}`
        };
    });
    return ddoc;
}
exports.addProvidersToDesignDoc = addProvidersToDesignDoc;
/** Capitalizes the first letter of a string */
function capitalizeFirstLetter(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}
exports.capitalizeFirstLetter = capitalizeFirstLetter;
/**
 * Access nested JavaScript objects with string key
 * http://stackoverflow.com/questions/6491463/accessing-nested-javascript-objects-with-string-key
 *
 * @param obj The base object you want to get a reference to
 * @param str The string addressing the part of the object you want
 * @return a reference to the requested key or undefined if not found
 */
function getObjectRef(obj, str) {
    str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
    str = str.replace(/^\./, ''); // strip a leading dot
    const pList = str.split('.');
    while (pList.length) {
        const n = pList.shift();
        if (n in obj) {
            obj = obj[n];
        }
        else {
            return;
        }
    }
    return obj;
}
exports.getObjectRef = getObjectRef;
/**
 * Dynamically set property of nested object
 * http://stackoverflow.com/questions/18936915/dynamically-set-property-of-nested-object
 *
 * @param obj The base object you want to set the property in
 * @param str The string addressing the part of the object you want
 * @param val The value you want to set the property to
 * @return the value the reference was set to
 */
function setObjectRef(obj, str, val) {
    str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
    str = str.replace(/^\./, ''); // strip a leading dot
    const pList = str.split('.');
    const len = pList.length;
    for (let i = 0; i < len - 1; i++) {
        const elem = pList[i];
        if (!obj[elem]) {
            obj[elem] = {};
        }
        obj = obj[elem];
    }
    obj[pList[len - 1]] = val;
    return val;
}
exports.setObjectRef = setObjectRef;
/**
 * Dynamically delete property of nested object
 *
 * @param obj The base object you want to set the property in
 * @param str The string addressing the part of the object you want
 * @return true if successful
 */
function delObjectRef(obj, str) {
    str = str.replace(/\[(\w+)\]/g, '.$1'); // convert indexes to properties
    str = str.replace(/^\./, ''); // strip a leading dot
    const pList = str.split('.');
    const len = pList.length;
    for (let i = 0; i < len - 1; i++) {
        const elem = pList[i];
        if (!obj[elem]) {
            return false;
        }
        obj = obj[elem];
    }
    delete obj[pList[len - 1]];
    return true;
}
exports.delObjectRef = delObjectRef;
/**
 * Concatenates two arrays and removes duplicate elements
 *
 * @param a First array
 * @param b Second array
 * @return  resulting array
 */
function arrayUnion(a, b) {
    const result = a.concat(b);
    for (let i = 0; i < result.length; ++i) {
        for (let j = i + 1; j < result.length; ++j) {
            if (result[i] === result[j])
                result.splice(j--, 1);
        }
    }
    return result;
}
exports.arrayUnion = arrayUnion;
