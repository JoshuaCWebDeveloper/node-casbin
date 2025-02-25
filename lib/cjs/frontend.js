"use strict";
// Copyright 2020 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
Object.defineProperty(exports, "__esModule", { value: true });
exports.casbinJsGetPermissionForUser = void 0;
const util_1 = require("./util");
/**
 * Experiment!
 * getPermissionForCasbinJs returns a string include the whole model.
 * You can pass the returned string to the frontend and manage your webpage widgets and APIs with Casbin.js.
 * @param e the initialized enforcer
 * @param user the user
 */
async function casbinJsGetPermissionForUser(e, user) {
    var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
    const obj = {};
    const m = e.getModel().model;
    let s = '';
    s += '[request_definition]\n';
    s += `r = ${(_b = (_a = m.get('r')) === null || _a === void 0 ? void 0 : _a.get('r')) === null || _b === void 0 ? void 0 : _b.value.replace(/_/g, '.')}\n`;
    s += '[policy_definition]\n';
    s += `p = ${(_d = (_c = m.get('p')) === null || _c === void 0 ? void 0 : _c.get('p')) === null || _d === void 0 ? void 0 : _d.value.replace(/_/g, '.')}\n`;
    if (((_e = m.get('g')) === null || _e === void 0 ? void 0 : _e.get('g')) !== undefined) {
        s += '[role_definition]\n';
        s += `g = ${(_g = (_f = m.get('g')) === null || _f === void 0 ? void 0 : _f.get('g')) === null || _g === void 0 ? void 0 : _g.value}\n`;
    }
    s += '[policy_effect]\n';
    s += `e = ${(_j = (_h = m.get('e')) === null || _h === void 0 ? void 0 : _h.get('e')) === null || _j === void 0 ? void 0 : _j.value.replace(/_/g, '.')}\n`;
    s += '[matchers]\n';
    s += `m = ${(_l = (_k = m.get('m')) === null || _k === void 0 ? void 0 : _k.get('m')) === null || _l === void 0 ? void 0 : _l.value.replace(/_/g, '.')}`;
    obj['m'] = s;
    obj['p'] = util_1.deepCopy(await e.getPolicy());
    for (const arr of obj['p']) {
        arr.splice(0, 0, 'p');
    }
    return JSON.stringify(obj);
}
exports.casbinJsGetPermissionForUser = casbinJsGetPermissionForUser;
