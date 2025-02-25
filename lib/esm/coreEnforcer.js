// Copyright 2018 The Casbin Authors. All Rights Reserved.
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
import { compile, compileAsync, addBinaryOp } from 'expression-eval';
import { DefaultEffector, Effect } from './effect';
import { FunctionMap, newModel } from './model';
import { DefaultRoleManager } from './rbac';
import { escapeAssertion, generateGFunction, getEvalValue, hasEval, replaceEval, generatorRunSync, generatorRunAsync, customIn, bracketCompatible, } from './util';
import { getLogger, logPrint } from './log';
/**
 * CoreEnforcer defines the core functionality of an enforcer.
 */
export class CoreEnforcer {
    constructor() {
        this.fm = FunctionMap.loadFunctionMap();
        this.eft = new DefaultEffector();
        this.matcherMap = new Map();
        this.watcher = null;
        this.rmMap = new Map([['g', new DefaultRoleManager(10)]]);
        this.enabled = true;
        this.autoSave = true;
        this.autoBuildRoleLinks = true;
        this.autoNotifyWatcher = true;
    }
    getExpression(asyncCompile, exp) {
        const matcherKey = `${asyncCompile ? 'ASYNC[' : 'SYNC['}${exp}]`;
        addBinaryOp('in', 1, customIn);
        let expression = this.matcherMap.get(matcherKey);
        if (!expression) {
            exp = bracketCompatible(exp);
            expression = asyncCompile ? compileAsync(exp) : compile(exp);
            this.matcherMap.set(matcherKey, expression);
        }
        return expression;
    }
    /**
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model,
     * so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
     */
    loadModel() {
        this.model = newModel();
        this.model.loadModel(this.modelPath);
        this.model.printModel();
    }
    /**
     * getModel gets the current model.
     *
     * @return the model of the enforcer.
     */
    getModel() {
        return this.model;
    }
    /**
     * setModel sets the current model.
     *
     * @param m the model.
     */
    setModel(m) {
        this.model = m;
    }
    /**
     * getAdapter gets the current adapter.
     *
     * @return the adapter of the enforcer.
     */
    getAdapter() {
        return this.adapter;
    }
    /**
     * setAdapter sets the current adapter.
     *
     * @param adapter the adapter.
     */
    setAdapter(adapter) {
        this.adapter = adapter;
    }
    /**
     * setWatcher sets the current watcher.
     *
     * @param watcher the watcher.
     */
    setWatcher(watcher) {
        this.watcher = watcher;
        watcher.setUpdateCallback(async () => await this.loadPolicy());
    }
    /**
     * setRoleManager sets the current role manager.
     *
     * @param rm the role manager.
     */
    setRoleManager(rm) {
        this.rmMap.set('g', rm);
    }
    /**
     * getRoleManager gets the current role manager.
     */
    getRoleManager() {
        return this.rmMap.get('g');
    }
    /**
     * getNamedRoleManager gets role manager by name.
     */
    getNamedRoleManager(name) {
        return this.rmMap.get(name);
    }
    /**
     * setEffector sets the current effector.
     *
     * @param eft the effector.
     */
    setEffector(eft) {
        this.eft = eft;
    }
    /**
     * clearPolicy clears all policy.
     */
    clearPolicy() {
        this.model.clearPolicy();
    }
    initRmMap() {
        this.rmMap = new Map();
        const rm = this.model.model.get('g');
        if (rm) {
            for (const ptype of rm.keys()) {
                this.rmMap.set(ptype, new DefaultRoleManager(10));
            }
        }
    }
    sortPolicies() {
        var _a, _b, _c, _d;
        const policy = (_b = (_a = this.model.model.get('p')) === null || _a === void 0 ? void 0 : _a.get('p')) === null || _b === void 0 ? void 0 : _b.policy;
        const tokens = (_d = (_c = this.model.model.get('p')) === null || _c === void 0 ? void 0 : _c.get('p')) === null || _d === void 0 ? void 0 : _d.tokens;
        if (policy && tokens) {
            const priorityIndex = tokens.indexOf('p_priority');
            if (priorityIndex !== -1) {
                policy.sort((a, b) => {
                    return parseInt(a[priorityIndex], 10) - parseInt(b[priorityIndex], 10);
                });
            }
        }
    }
    /**
     * loadPolicy reloads the policy from file/database.
     */
    async loadPolicy() {
        this.model.clearPolicy();
        await this.adapter.loadPolicy(this.model);
        this.sortPolicies();
        this.initRmMap();
        if (this.autoBuildRoleLinks) {
            await this.buildRoleLinksInternal();
        }
    }
    /**
     * loadFilteredPolicy reloads a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be loaded.
     */
    // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
    async loadFilteredPolicy(filter) {
        this.model.clearPolicy();
        return this.loadIncrementalFilteredPolicy(filter);
    }
    /**
     * LoadIncrementalFilteredPolicy append a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be appended.
     */
    // eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
    async loadIncrementalFilteredPolicy(filter) {
        if ('isFiltered' in this.adapter) {
            await this.adapter.loadFilteredPolicy(this.model, filter);
        }
        else {
            throw new Error('filtered policies are not supported by this adapter');
        }
        this.sortPolicies();
        this.initRmMap();
        if (this.autoBuildRoleLinks) {
            await this.buildRoleLinksInternal();
        }
        return true;
    }
    /**
     * isFiltered returns true if the loaded policy has been filtered.
     *
     * @return if the loaded policy has been filtered.
     */
    isFiltered() {
        if ('isFiltered' in this.adapter) {
            return this.adapter.isFiltered();
        }
        return false;
    }
    /**
     * savePolicy saves the current policy (usually after changed with
     * Casbin API) back to file/database.
     */
    async savePolicy() {
        if (this.isFiltered()) {
            throw new Error('Cannot save a filtered policy');
        }
        const flag = await this.adapter.savePolicy(this.model);
        if (!flag) {
            return false;
        }
        if (this.watcher) {
            return await this.watcher.update();
        }
        return true;
    }
    /**
     * enableEnforce changes the enforcing state of Casbin, when Casbin is
     * disabled, all access will be allowed by the enforce() function.
     *
     * @param enable whether to enable the enforcer.
     */
    enableEnforce(enable) {
        this.enabled = enable;
    }
    /**
     * enableLog changes whether to print Casbin log to the standard output.
     *
     * @param enable whether to enable Casbin's log.
     */
    enableLog(enable) {
        getLogger().enableLog(enable);
    }
    /**
     * enableAutoSave controls whether to save a policy rule automatically to
     * the adapter when it is added or removed.
     *
     * @param autoSave whether to enable the AutoSave feature.
     */
    enableAutoSave(autoSave) {
        this.autoSave = autoSave;
    }
    /**
     * enableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
     * @param enable whether to enable the AutoNotifyWatcher feature.
     */
    enableAutoNotifyWatcher(enable) {
        this.autoNotifyWatcher = enable;
    }
    /**
     * enableAutoBuildRoleLinks controls whether to save a policy rule
     * automatically to the adapter when it is added or removed.
     *
     * @param autoBuildRoleLinks whether to automatically build the role links.
     */
    enableAutoBuildRoleLinks(autoBuildRoleLinks) {
        this.autoBuildRoleLinks = autoBuildRoleLinks;
    }
    /**
     * add matching function to RoleManager by ptype
     * @param ptype g
     * @param fn the function will be added
     */
    async addNamedMatchingFunc(ptype, fn) {
        const rm = this.rmMap.get(ptype);
        if (rm) {
            return await rm.addMatchingFunc(fn);
        }
        throw Error('Target ptype not found.');
    }
    /**
     * add domain matching function to RoleManager by ptype
     * @param ptype g
     * @param fn the function will be added
     */
    async addNamedDomainMatchingFunc(ptype, fn) {
        const rm = this.rmMap.get(ptype);
        if (rm) {
            return await rm.addDomainMatchingFunc(fn);
        }
    }
    /**
     * buildRoleLinks manually rebuild the role inheritance relations.
     */
    async buildRoleLinks() {
        return this.buildRoleLinksInternal();
    }
    /**
     * buildIncrementalRoleLinks provides incremental build the role inheritance relations.
     * @param op policy operation
     * @param ptype g
     * @param rules policies
     */
    async buildIncrementalRoleLinks(op, ptype, rules) {
        let rm = this.rmMap.get(ptype);
        if (!rm) {
            rm = new DefaultRoleManager(10);
            this.rmMap.set(ptype, rm);
        }
        await this.model.buildIncrementalRoleLinks(rm, op, 'g', ptype, rules);
    }
    async buildRoleLinksInternal() {
        for (const rm of this.rmMap.values()) {
            await rm.clear();
            await this.model.buildRoleLinks(this.rmMap);
        }
    }
    *privateEnforce(asyncCompile = true, explain = false, ...rvals) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j;
        if (!this.enabled) {
            return true;
        }
        let explainIndex = -1;
        const functions = {};
        this.fm.getFunctions().forEach((value, key) => {
            functions[key] = value;
        });
        const astMap = this.model.model.get('g');
        astMap === null || astMap === void 0 ? void 0 : astMap.forEach((value, key) => {
            const rm = value.rm;
            functions[key] = generateGFunction(rm);
        });
        const expString = (_b = (_a = this.model.model.get('m')) === null || _a === void 0 ? void 0 : _a.get('m')) === null || _b === void 0 ? void 0 : _b.value;
        if (!expString) {
            throw new Error('Unable to find matchers in model');
        }
        const effectExpr = (_d = (_c = this.model.model.get('e')) === null || _c === void 0 ? void 0 : _c.get('e')) === null || _d === void 0 ? void 0 : _d.value;
        if (!effectExpr) {
            throw new Error('Unable to find policy_effect in model');
        }
        const HasEval = hasEval(expString);
        let expression = undefined;
        const p = (_e = this.model.model.get('p')) === null || _e === void 0 ? void 0 : _e.get('p');
        const policyLen = (_f = p === null || p === void 0 ? void 0 : p.policy) === null || _f === void 0 ? void 0 : _f.length;
        const rTokens = (_h = (_g = this.model.model.get('r')) === null || _g === void 0 ? void 0 : _g.get('r')) === null || _h === void 0 ? void 0 : _h.tokens;
        const rTokensLen = rTokens === null || rTokens === void 0 ? void 0 : rTokens.length;
        const effectStream = this.eft.newStream(effectExpr);
        if (policyLen && policyLen !== 0) {
            for (let i = 0; i < policyLen; i++) {
                const parameters = {};
                if ((rTokens === null || rTokens === void 0 ? void 0 : rTokens.length) !== rvals.length) {
                    throw new Error(`invalid request size: expected ${rTokensLen}, got ${rvals.length}, rvals: ${rvals}"`);
                }
                rTokens.forEach((token, j) => {
                    parameters[token] = rvals[j];
                });
                p === null || p === void 0 ? void 0 : p.tokens.forEach((token, j) => {
                    parameters[token] = p === null || p === void 0 ? void 0 : p.policy[i][j];
                });
                if (HasEval) {
                    const ruleNames = getEvalValue(expString);
                    let expWithRule = expString;
                    for (const ruleName of ruleNames) {
                        if (ruleName in parameters) {
                            const rule = escapeAssertion(parameters[ruleName]);
                            expWithRule = replaceEval(expWithRule, ruleName, rule);
                        }
                        else {
                            throw new Error(`${ruleName} not in ${parameters}`);
                        }
                    }
                    expression = this.getExpression(asyncCompile, expWithRule);
                }
                else {
                    if (expression === undefined) {
                        expression = this.getExpression(asyncCompile, expString);
                    }
                }
                const context = Object.assign(Object.assign({}, parameters), functions);
                const result = asyncCompile ? yield expression(context) : expression(context);
                let eftRes;
                switch (typeof result) {
                    case 'boolean':
                        eftRes = result ? Effect.Allow : Effect.Indeterminate;
                        break;
                    case 'number':
                        if (result === 0) {
                            eftRes = Effect.Indeterminate;
                        }
                        else {
                            eftRes = result;
                        }
                        break;
                    default:
                        throw new Error('matcher result should be boolean or number');
                }
                const eft = parameters['p_eft'];
                if (eft && eftRes === Effect.Allow) {
                    if (eft === 'allow') {
                        eftRes = Effect.Allow;
                    }
                    else if (eft === 'deny') {
                        eftRes = Effect.Deny;
                    }
                    else {
                        eftRes = Effect.Indeterminate;
                    }
                }
                const [res, done] = effectStream.pushEffect(eftRes);
                if (done) {
                    explainIndex = i;
                    break;
                }
            }
        }
        else {
            explainIndex = 0;
            const parameters = {};
            rTokens === null || rTokens === void 0 ? void 0 : rTokens.forEach((token, j) => {
                parameters[token] = rvals[j];
            });
            (_j = p === null || p === void 0 ? void 0 : p.tokens) === null || _j === void 0 ? void 0 : _j.forEach((token) => {
                parameters[token] = '';
            });
            expression = this.getExpression(asyncCompile, expString);
            const context = Object.assign(Object.assign({}, parameters), functions);
            const result = asyncCompile ? yield expression(context) : expression(context);
            if (result) {
                effectStream.pushEffect(Effect.Allow);
            }
            else {
                effectStream.pushEffect(Effect.Indeterminate);
            }
        }
        const res = effectStream.current();
        // only generate the request --> result string if the message
        // is going to be logged.
        if (getLogger().isEnable()) {
            let reqStr = 'Request: ';
            for (let i = 0; i < rvals.length; i++) {
                if (i !== rvals.length - 1) {
                    reqStr += `${rvals[i]}, `;
                }
                else {
                    reqStr += rvals[i];
                }
            }
            reqStr += ` ---> ${res}`;
            logPrint(reqStr);
        }
        if (explain) {
            if (explainIndex === -1) {
                return [res, []];
            }
            return [res, p === null || p === void 0 ? void 0 : p.policy[explainIndex]];
        }
        return res;
    }
    /**
     * If the matchers does not contain an asynchronous method, call it faster.
     *
     * enforceSync decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    enforceSync(...rvals) {
        return generatorRunSync(this.privateEnforce(false, false, ...rvals));
    }
    /**
     * If the matchers does not contain an asynchronous method, call it faster.
     *
     * enforceSync decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request and the reason rule.
     */
    enforceExSync(...rvals) {
        return generatorRunSync(this.privateEnforce(false, true, ...rvals));
    }
    /**
     * Same as enforceSync. To be removed.
     */
    enforceWithSyncCompile(...rvals) {
        return this.enforceSync(...rvals);
    }
    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    async enforce(...rvals) {
        return generatorRunAsync(this.privateEnforce(true, false, ...rvals));
    }
    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request and the reason rule.
     */
    async enforceEx(...rvals) {
        return generatorRunAsync(this.privateEnforce(true, true, ...rvals));
    }
}
