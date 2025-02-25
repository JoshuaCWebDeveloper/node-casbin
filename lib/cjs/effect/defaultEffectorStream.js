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
exports.DefaultEffectorStream = void 0;
const effector_1 = require("./effector");
/**
 * DefaultEffectorStream is the default implementation of EffectorStream.
 */
class DefaultEffectorStream {
    constructor(expr) {
        this.done = false;
        this.res = false;
        this.expr = expr;
    }
    current() {
        return this.res;
    }
    pushEffect(eft) {
        switch (this.expr) {
            case 'some(where (p_eft == allow))':
                if (eft === effector_1.Effect.Allow) {
                    this.res = true;
                    this.done = true;
                }
                break;
            case '!some(where (p_eft == deny))':
                this.res = true;
                if (eft === effector_1.Effect.Deny) {
                    this.res = false;
                    this.done = true;
                }
                break;
            case 'some(where (p_eft == allow)) && !some(where (p_eft == deny))':
                if (eft === effector_1.Effect.Allow) {
                    this.res = true;
                }
                else if (eft === effector_1.Effect.Deny) {
                    this.res = false;
                    this.done = true;
                }
                break;
            case 'priority(p_eft) || deny':
                if (eft !== effector_1.Effect.Indeterminate) {
                    this.res = eft === effector_1.Effect.Allow;
                    this.done = true;
                }
                break;
            default:
                throw new Error('unsupported effect');
        }
        return [this.res, this.done];
    }
}
exports.DefaultEffectorStream = DefaultEffectorStream;
