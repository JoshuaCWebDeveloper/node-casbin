"use strict";
// Copyright 2017 The casbin Authors. All Rights Reserved.
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
exports.Assertion = void 0;
const rbac = require("../rbac");
const log_1 = require("../log");
const model_1 = require("./model");
// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act
class Assertion {
    /**
     * constructor is the constructor for Assertion.
     */
    constructor() {
        this.key = '';
        this.value = '';
        this.tokens = [];
        this.policy = [];
        this.rm = new rbac.DefaultRoleManager(10);
    }
    async buildIncrementalRoleLinks(rm, op, rules) {
        this.rm = rm;
        const count = (this.value.match(/_/g) || []).length;
        if (count < 2) {
            throw new Error('the number of "_" in role definition should be at least 2');
        }
        for (let rule of rules) {
            if (rule.length < count) {
                throw new Error('grouping policy elements do not meet role definition');
            }
            if (rule.length > count) {
                rule = rule.slice(0, count);
            }
            switch (op) {
                case model_1.PolicyOp.PolicyAdd:
                    await this.rm.addLink(rule[0], rule[1], ...rule.slice(2));
                    break;
                case model_1.PolicyOp.PolicyRemove:
                    await this.rm.deleteLink(rule[0], rule[1], ...rule.slice(2));
                    break;
                default:
                    throw new Error('unsupported operation');
            }
        }
    }
    async buildRoleLinks(rm) {
        this.rm = rm;
        const count = (this.value.match(/_/g) || []).length;
        if (count < 2) {
            throw new Error('the number of "_" in role definition should be at least 2');
        }
        for (let rule of this.policy) {
            if (rule.length > count) {
                rule = rule.slice(0, count);
            }
            await this.rm.addLink(rule[0], rule[1], ...rule.slice(2));
        }
        log_1.logPrint(`Role links for: ${this.key}`);
        await this.rm.printRoles();
    }
}
exports.Assertion = Assertion;
