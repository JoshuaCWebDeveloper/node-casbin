"use strict";
// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the 'License');
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an 'AS IS' BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
Object.defineProperty(exports, "__esModule", { value: true });
exports.globMatch = exports.keyMatch4Func = exports.generateGFunction = exports.ipMatchFunc = exports.regexMatchFunc = exports.keyMatch3Func = exports.keyGet2Func = exports.keyMatch2Func = exports.keyGetFunc = exports.keyMatchFunc = void 0;
const ip_1 = require("./ip");
const picomatch = require("picomatch");
// regexMatch determines whether key1 matches the pattern of key2 in regular expression.
function regexMatch(key1, key2) {
    return new RegExp(key2).test(key1);
}
// keyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path),
// key2 can contain a *.
// For example, '/foo/bar' matches '/foo/*'
function keyMatch(key1, key2) {
    const pos = key2.indexOf('*');
    if (pos === -1) {
        return key1 === key2;
    }
    if (key1.length > pos) {
        return key1.slice(0, pos) === key2.slice(0, pos);
    }
    return key1 === key2.slice(0, pos);
}
// keyMatchFunc is the wrapper for keyMatch.
function keyMatchFunc(...args) {
    const [arg0, arg1] = args;
    const name1 = (arg0 || '').toString();
    const name2 = (arg1 || '').toString();
    return keyMatch(name1, name2);
}
exports.keyMatchFunc = keyMatchFunc;
// KeyGet returns the matched part
// For example, "/foo/bar/foo" matches "/foo/*"
// "bar/foo" will been returned
function keyGet(key1, key2) {
    const pos = key2.indexOf('*');
    if (pos === -1) {
        return '';
    }
    if (key1.length > pos) {
        if (key1.slice(0, pos) === key2.slice(0, pos)) {
            return key1.slice(pos, key1.length);
        }
    }
    return '';
}
// keyGetFunc is the wrapper for keyGet.
function keyGetFunc(...args) {
    const [arg0, arg1] = args;
    const name1 = (arg0 || '').toString();
    const name2 = (arg1 || '').toString();
    return keyGet(name1, name2);
}
exports.keyGetFunc = keyGetFunc;
// keyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path),
// key2 can contain a *.
// For example, '/foo/bar' matches '/foo/*', '/resource1' matches '/:resource'
function keyMatch2(key1, key2) {
    key2 = key2.replace(/\/\*/g, '/.*');
    const regexp = new RegExp(/(.*):[^/]+(.*)/g);
    for (;;) {
        if (!key2.includes('/:')) {
            break;
        }
        key2 = key2.replace(regexp, '$1[^/]+$2');
    }
    if (key2 === '*') {
        key2 = '(.*)';
    }
    return regexMatch(key1, '^' + key2 + '$');
}
// keyMatch2Func is the wrapper for keyMatch2.
function keyMatch2Func(...args) {
    const [arg0, arg1] = args;
    const name1 = (arg0 || '').toString();
    const name2 = (arg1 || '').toString();
    return keyMatch2(name1, name2);
}
exports.keyMatch2Func = keyMatch2Func;
// KeyGet2 returns value matched pattern
// For example, "/resource1" matches "/:resource"
// if the pathVar == "resource", then "resource1" will be returned
function keyGet2(key1, key2, pathVar) {
    if (keyMatch2(key1, key2)) {
        const re = new RegExp('[^/]+', 'g');
        const keys = key2.match(re);
        const values = key1.match(re);
        if (!keys || !values) {
            return '';
        }
        const index = keys.indexOf(`:${pathVar}`);
        if (index === -1) {
            return '';
        }
        return values[index];
    }
    else {
        return '';
    }
}
function keyGet2Func(...args) {
    const [arg0, arg1, arg2] = args;
    const name1 = (arg0 || '').toString();
    const name2 = (arg1 || '').toString();
    const name3 = (arg2 || '').toString();
    return keyGet2(name1, name2, name3);
}
exports.keyGet2Func = keyGet2Func;
// keyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, '/foo/bar' matches '/foo/*', '/resource1' matches '/{resource}'
function keyMatch3(key1, key2) {
    key2 = key2.replace(/\/\*/g, '/.*');
    const regexp = new RegExp(/(.*){[^/]+}(.*)/g);
    for (;;) {
        if (!key2.includes('/{')) {
            break;
        }
        key2 = key2.replace(regexp, '$1[^/]+$2');
    }
    return regexMatch(key1, '^' + key2 + '$');
}
// keyMatch3Func is the wrapper for keyMatch3.
function keyMatch3Func(...args) {
    const [arg0, arg1] = args;
    const name1 = (arg0 || '').toString();
    const name2 = (arg1 || '').toString();
    return keyMatch3(name1, name2);
}
exports.keyMatch3Func = keyMatch3Func;
// keyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// Besides what keyMatch3 does, keyMatch4 can also match repeated patterns:
// "/parent/123/child/123" matches "/parent/{id}/child/{id}"
// "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
// But keyMatch3 will match both.
function keyMatch4(key1, key2) {
    key2 = key2.replace(/\/\*/g, '/.*');
    const tokens = [];
    let j = -1;
    for (let i = 0; i < key2.length; i++) {
        const c = key2.charAt(i);
        if (c === '{') {
            j = i;
        }
        else if (c === '}') {
            tokens.push(key2.substring(j, i + 1));
        }
    }
    let regexp = new RegExp(/(.*){[^/]+}(.*)/g);
    for (;;) {
        if (!key2.includes('/{')) {
            break;
        }
        key2 = key2.replace(regexp, '$1([^/]+)$2');
    }
    regexp = new RegExp('^' + key2 + '$');
    let values = regexp.exec(key1);
    if (!values) {
        return false;
    }
    values = values.slice(1);
    if (tokens.length !== values.length) {
        throw new Error('KeyMatch4: number of tokens is not equal to number of values');
    }
    const m = new Map();
    tokens.forEach((n, index) => {
        const key = tokens[index];
        let v = m.get(key);
        if (!v) {
            v = [];
        }
        if (values) {
            v.push(values[index]);
        }
        m.set(key, v);
    });
    for (const value of m.values()) {
        if (value.length > 1) {
            for (let i = 1; i < values.length; i++) {
                if (values[i] !== values[0]) {
                    return false;
                }
            }
        }
    }
    return true;
}
// keyMatch4Func is the wrapper for keyMatch4.
function keyMatch4Func(...args) {
    const [arg0, arg1] = args;
    const name1 = (arg0 || '').toString();
    const name2 = (arg1 || '').toString();
    return keyMatch4(name1, name2);
}
exports.keyMatch4Func = keyMatch4Func;
// regexMatchFunc is the wrapper for regexMatch.
function regexMatchFunc(...args) {
    const [arg0, arg1] = args;
    const name1 = (arg0 || '').toString();
    const name2 = (arg1 || '').toString();
    return regexMatch(name1, name2);
}
exports.regexMatchFunc = regexMatchFunc;
// ipMatch determines whether IP address ip1 matches the pattern of IP address ip2,
// ip2 can be an IP address or a CIDR pattern.
// For example, '192.168.2.123' matches '192.168.2.0/24'
function ipMatch(ip1, ip2) {
    // check ip1
    if (!(ip_1.ip.isV4Format(ip1) || ip_1.ip.isV6Format(ip1))) {
        throw new Error('invalid argument: ip1 in ipMatch() function is not an IP address.');
    }
    // check ip2
    const cidrParts = ip2.split('/');
    if (cidrParts.length === 2) {
        return ip_1.ip.cidrSubnet(ip2).contains(ip1);
    }
    else {
        if (!(ip_1.ip.isV4Format(ip2) || ip_1.ip.isV6Format(ip2))) {
            console.log(ip2);
            throw new Error('invalid argument: ip2 in ipMatch() function is not an IP address.');
        }
        return ip_1.ip.isEqual(ip1, ip2);
    }
}
// ipMatchFunc is the wrapper for ipMatch.
function ipMatchFunc(...args) {
    const [arg0, arg1] = args;
    const ip1 = (arg0 || '').toString();
    const ip2 = (arg1 || '').toString();
    return ipMatch(ip1, ip2);
}
exports.ipMatchFunc = ipMatchFunc;
/**
 * Returns true if the specified `string` matches the given glob `pattern`.
 *
 * @param string String to match
 * @param pattern Glob pattern to use for matching.
 * @returns Returns true if the string matches the glob pattern.
 *
 * @example
 * ```javascript
 * globMatch("abc.conf", "*.conf") => true
 * ```
 */
function globMatch(string, pattern) {
    return picomatch(pattern)(string);
}
exports.globMatch = globMatch;
// generateGFunction is the factory method of the g(_, _) function.
function generateGFunction(rm) {
    const memorized = new Map();
    return async function func(...args) {
        const key = args.toString();
        let value = memorized.get(key);
        if (value) {
            return value;
        }
        const [arg0, arg1] = args;
        const name1 = (arg0 || '').toString();
        const name2 = (arg1 || '').toString();
        if (!rm) {
            value = name1 === name2;
        }
        else if (args.length === 2) {
            value = await rm.hasLink(name1, name2);
        }
        else {
            const domain = args[2].toString();
            value = await rm.hasLink(name1, name2, domain);
        }
        memorized.set(key, value);
        return value;
    };
}
exports.generateGFunction = generateGFunction;
