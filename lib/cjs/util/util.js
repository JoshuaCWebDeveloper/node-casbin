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
exports.bracketCompatible = exports.customIn = exports.deepCopy = exports.generatorRunAsync = exports.generatorRunSync = exports.getEvalValue = exports.replaceEval = exports.hasEval = exports.writeFile = exports.readFile = exports.setEquals = exports.paramsToString = exports.arrayToString = exports.arrayRemoveDuplicates = exports.array2DEquals = exports.arrayEquals = exports.removeComments = exports.escapeAssertion = void 0;
const fs = require("fs");
// escapeAssertion escapes the dots in the assertion,
// because the expression evaluation doesn't support such variable names.
function escapeAssertion(s) {
    s = s.replace(/r\./g, 'r_');
    s = s.replace(/p\./g, 'p_');
    return s;
}
exports.escapeAssertion = escapeAssertion;
// removeComments removes the comments starting with # in the text.
function removeComments(s) {
    const pos = s.indexOf('#');
    return pos > -1 ? s.slice(0, pos).trim() : s;
}
exports.removeComments = removeComments;
// arrayEquals determines whether two string arrays are identical.
function arrayEquals(a = [], b = []) {
    const aLen = a.length;
    const bLen = b.length;
    if (aLen !== bLen) {
        return false;
    }
    for (let i = 0; i < aLen; i++) {
        if (a[i] !== b[i]) {
            return false;
        }
    }
    return true;
}
exports.arrayEquals = arrayEquals;
// array2DEquals determines whether two 2-dimensional string arrays are identical.
function array2DEquals(a = [], b = []) {
    const aLen = a.length;
    const bLen = a.length;
    if (aLen !== bLen) {
        return false;
    }
    for (let i = 0; i < aLen; i++) {
        if (!arrayEquals(a[i], b[i])) {
            return false;
        }
    }
    return true;
}
exports.array2DEquals = array2DEquals;
// arrayRemoveDuplicates removes any duplicated elements in a string array.
function arrayRemoveDuplicates(s) {
    return [...new Set(s)];
}
exports.arrayRemoveDuplicates = arrayRemoveDuplicates;
// arrayToString gets a printable string for a string array.
function arrayToString(a) {
    return a.join(', ');
}
exports.arrayToString = arrayToString;
// paramsToString gets a printable string for variable number of parameters.
function paramsToString(...v) {
    return v.join(', ');
}
exports.paramsToString = paramsToString;
// setEquals determines whether two string sets are identical.
function setEquals(a, b) {
    return arrayEquals(a.sort(), b.sort());
}
exports.setEquals = setEquals;
// readFile return a promise for readFile.
function readFile(path, encoding) {
    return new Promise((resolve, reject) => {
        fs.readFile(path, encoding || 'utf8', (error, data) => {
            if (error) {
                reject(error);
            }
            resolve(data);
        });
    });
}
exports.readFile = readFile;
// writeFile return a promise for writeFile.
function writeFile(path, file, encoding) {
    return new Promise((resolve, reject) => {
        fs.writeFile(path, file, encoding || 'utf8', (error) => {
            if (error) {
                reject(error);
            }
            resolve(true);
        });
    });
}
exports.writeFile = writeFile;
const evalReg = new RegExp(/\beval\(([^),]*)\)/g);
// hasEval determine whether matcher contains function eval
function hasEval(s) {
    return evalReg.test(s);
}
exports.hasEval = hasEval;
// replaceEval replace function eval with the value of its parameters
function replaceEval(s, ruleName, rule) {
    return s.replace(`eval(${ruleName})`, '(' + rule + ')');
}
exports.replaceEval = replaceEval;
// getEvalValue returns the parameters of function eval
function getEvalValue(s) {
    const subMatch = s.match(evalReg);
    const rules = [];
    if (!subMatch) {
        return [];
    }
    for (const rule of subMatch) {
        const index = rule.indexOf('(');
        rules.push(rule.slice(index + 1, -1));
    }
    return rules;
}
exports.getEvalValue = getEvalValue;
// generatorRunSync handle generator function in Sync model and return value which is not Promise
function generatorRunSync(iterator) {
    let { value, done } = iterator.next();
    while (true) {
        if (value instanceof Promise) {
            throw new Error('cannot handle Promise in generatorRunSync, Please use generatorRunAsync');
        }
        if (!done) {
            const temp = value;
            ({ value, done } = iterator.next(temp));
        }
        else {
            return value;
        }
    }
}
exports.generatorRunSync = generatorRunSync;
// generatorRunAsync handle generator function in Async model and return Promise
async function generatorRunAsync(iterator) {
    let { value, done } = iterator.next();
    while (true) {
        if (!done) {
            const temp = await value;
            ({ value, done } = iterator.next(temp));
        }
        else {
            return value;
        }
    }
}
exports.generatorRunAsync = generatorRunAsync;
function deepCopy(obj) {
    if (typeof obj !== 'object')
        return;
    const newObj = obj instanceof Array ? [] : {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            newObj[key] = typeof obj[key] === 'object' ? deepCopy(obj[key]) : obj[key];
        }
    }
    return newObj;
}
exports.deepCopy = deepCopy;
function customIn(a, b) {
    if (b instanceof Array) {
        return b.includes(a);
    }
    return (a in b);
}
exports.customIn = customIn;
function bracketCompatible(exp) {
    // TODO: This function didn't support nested bracket.
    if (!(exp.includes(' in ') && exp.includes(' ('))) {
        return exp;
    }
    const re = / \([^)]*\)/g;
    const array = exp.split('');
    let reResult;
    while ((reResult = re.exec(exp)) !== null) {
        if (!reResult[0].includes(',')) {
            continue;
        }
        array[reResult.index + 1] = '[';
        array[re.lastIndex - 1] = ']';
    }
    exp = array.join('');
    return exp;
}
exports.bracketCompatible = bracketCompatible;
