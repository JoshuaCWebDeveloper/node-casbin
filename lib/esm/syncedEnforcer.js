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
import { Enforcer, newEnforcerWithClass } from './enforcer';
import AwaitLock from 'await-lock';
// SyncedEnforcer wraps Enforcer and provides synchronized access
export class SyncedEnforcer extends Enforcer {
    constructor() {
        super(...arguments);
        this.lock = new AwaitLock();
    }
    /**
     * setWatcher sets the current watcher.
     *
     * @param watcher the watcher.
     */
    setWatcher(watcher) {
        this.watcher = watcher;
        this.watcher.setUpdateCallback(() => this.loadPolicy());
    }
    /**
     * loadPolicy reloads the policy from file/database.
     */
    async loadPolicy() {
        await this.lock.acquireAsync();
        return super.loadPolicy().finally(() => this.lock.release());
    }
    /**
     * clearPolicy clears all policy.
     */
    clearPolicy() {
        this.lock
            .acquireAsync()
            .then(() => super.clearPolicy())
            .finally(() => this.lock.release());
    }
    /**
     * savePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
     */
    async savePolicy() {
        await this.lock.acquireAsync();
        return super.savePolicy().finally(() => this.lock.release());
    }
    /**
     * buildRoleLinks manually rebuild the role inheritance relations.
     */
    async buildRoleLinks() {
        await this.lock.acquireAsync();
        return super.buildRoleLinks().finally(() => this.lock.release());
    }
    /**
     * If the matchers does not contain an asynchronous method, call it faster.
     *
     * enforceWithSyncCompile decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    enforceWithSyncCompile(...rvals) {
        return super.enforceWithSyncCompile(...rvals);
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
        await this.lock.acquireAsync();
        return super.enforce(...rvals).finally(() => this.lock.release());
    }
    /**
     * getAllSubjects gets the list of subjects that show up in the current policy.
     *
     * @return all the subjects in "p" policy rules. It actually collects the
     *         0-index elements of "p" policy rules. So make sure your subject
     *         is the 0-index element, like (sub, obj, act). Duplicates are removed.
     */
    async getAllSubjects() {
        return this.getAllNamedSubjects('p');
    }
    /**
     * getAllNamedSubjects gets the list of subjects that show up in the currentnamed policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the subjects in policy rules of the ptype type. It actually
     *         collects the 0-index elements of the policy rules. So make sure
     *         your subject is the 0-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    async getAllNamedSubjects(ptype) {
        await this.lock.acquireAsync();
        return super.getAllNamedSubjects(ptype).finally(() => this.lock.release());
    }
    /**
     * getAllObjects gets the list of objects that show up in the current policy.
     *
     * @return all the objects in "p" policy rules. It actually collects the
     *         1-index elements of "p" policy rules. So make sure your object
     *         is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    async getAllObjects() {
        return this.getAllNamedObjects('p');
    }
    /**
     * getAllNamedObjects gets the list of objects that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the objects in policy rules of the ptype type. It actually
     *         collects the 1-index elements of the policy rules. So make sure
     *         your object is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    async getAllNamedObjects(ptype) {
        await this.lock.acquireAsync();
        return super.getAllNamedObjects(ptype).finally(() => this.lock.release());
    }
    /**
     * getAllActions gets the list of actions that show up in the current policy.
     *
     * @return all the actions in "p" policy rules. It actually collects
     *         the 2-index elements of "p" policy rules. So make sure your action
     *         is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    async getAllActions() {
        return this.getAllNamedActions('p');
    }
    /**
     * GetAllNamedActions gets the list of actions that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the actions in policy rules of the ptype type. It actually
     *         collects the 2-index elements of the policy rules. So make sure
     *         your action is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    async getAllNamedActions(ptype) {
        await this.lock.acquireAsync();
        return super.getAllNamedActions(ptype).finally(() => this.lock.release());
    }
    /**
     * getAllRoles gets the list of roles that show up in the current policy.
     *
     * @return all the roles in "g" policy rules. It actually collects
     *         the 1-index elements of "g" policy rules. So make sure your
     *         role is the 1-index element, like (sub, role).
     *         Duplicates are removed.
     */
    async getAllRoles() {
        return this.getAllNamedRoles('g');
    }
    /**
     * getAllNamedRoles gets the list of roles that show up in the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return all the subjects in policy rules of the ptype type. It actually
     *         collects the 0-index elements of the policy rules. So make
     *         sure your subject is the 0-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    async getAllNamedRoles(ptype) {
        await this.lock.acquireAsync();
        return super.getAllNamedRoles(ptype).finally(() => this.lock.release());
    }
    /**
     * getPolicy gets all the authorization rules in the policy.
     *
     * @return all the "p" policy rules.
     */
    async getPolicy() {
        return this.getNamedPolicy('p');
    }
    /**
     * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules.
     */
    async getFilteredPolicy(fieldIndex, ...fieldValues) {
        return this.getFilteredNamedPolicy('p', fieldIndex, ...fieldValues);
    }
    /**
     * getNamedPolicy gets all the authorization rules in the named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return the "p" policy rules of the specified ptype.
     */
    async getNamedPolicy(ptype) {
        await this.lock.acquireAsync();
        return super.getNamedPolicy(ptype).finally(() => this.lock.release());
    }
    /**
     * getFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules of the specified ptype.
     */
    async getFilteredNamedPolicy(ptype, fieldIndex, ...fieldValues) {
        await this.lock.acquireAsync();
        return super.getFilteredNamedPolicy(ptype, fieldIndex, ...fieldValues).finally(() => this.lock.release());
    }
    /**
     * getGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @return all the "g" policy rules.
     */
    async getGroupingPolicy() {
        return this.getNamedGroupingPolicy('g');
    }
    /**
     * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value "" means not to match this field.
     * @return the filtered "g" policy rules.
     */
    async getFilteredGroupingPolicy(fieldIndex, ...fieldValues) {
        return this.getFilteredNamedGroupingPolicy('g', fieldIndex, ...fieldValues);
    }
    /**
     * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return the "g" policy rules of the specified ptype.
     */
    async getNamedGroupingPolicy(ptype) {
        await this.lock.acquireAsync();
        return super.getNamedGroupingPolicy(ptype).finally(() => this.lock.release());
    }
    /**
     * getFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "g" policy rules of the specified ptype.
     */
    async getFilteredNamedGroupingPolicy(ptype, fieldIndex, ...fieldValues) {
        await this.lock.acquireAsync();
        return super.getFilteredNamedGroupingPolicy(ptype, fieldIndex, ...fieldValues).finally(() => this.lock.release());
    }
    /**
     * hasPolicy determines whether an authorization rule exists.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return whether the rule exists.
     */
    async hasPolicy(...params) {
        return this.hasNamedPolicy('p', ...params);
    }
    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return whether the rule exists.
     */
    async hasNamedPolicy(ptype, ...params) {
        await this.lock.acquireAsync();
        return super.hasNamedPolicy(ptype, ...params).finally(() => this.lock.release());
    }
    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    async addPolicy(...params) {
        return this.addNamedPolicy('p', ...params);
    }
    /**
     * addNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    async addNamedPolicy(ptype, ...params) {
        await this.lock.acquireAsync();
        return super.addNamedPolicy(ptype, ...params).finally(() => this.lock.release());
    }
    /**
     * removePolicy removes an authorization rule from the current policy.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    async removePolicy(...params) {
        return this.removeNamedPolicy('p', ...params);
    }
    /**
     * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    async removeFilteredPolicy(fieldIndex, ...fieldValues) {
        return this.removeFilteredNamedPolicy('p', fieldIndex, ...fieldValues);
    }
    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    async removeNamedPolicy(ptype, ...params) {
        await this.lock.acquireAsync();
        return this.removePolicyInternal('p', ptype, params).finally(() => this.lock.release());
    }
    /**
     * removeFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    async removeFilteredNamedPolicy(ptype, fieldIndex, ...fieldValues) {
        await this.lock.acquireAsync();
        return super.removeFilteredNamedPolicy(ptype, fieldIndex, ...fieldValues).finally(() => this.lock.release());
    }
    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return whether the rule exists.
     */
    async hasGroupingPolicy(...params) {
        return this.hasNamedGroupingPolicy('g', ...params);
    }
    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return whether the rule exists.
     */
    async hasNamedGroupingPolicy(ptype, ...params) {
        await this.lock.acquireAsync();
        return super.hasNamedGroupingPolicy(ptype, ...params).finally(() => this.lock.release());
    }
    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    async addGroupingPolicy(...params) {
        return this.addNamedGroupingPolicy('g', ...params);
    }
    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    async addNamedGroupingPolicy(ptype, ...params) {
        await this.lock.acquireAsync();
        return super.addNamedGroupingPolicy(ptype, ...params).finally(() => this.lock.release());
    }
    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    async removeGroupingPolicy(...params) {
        return this.removeNamedGroupingPolicy('g', ...params);
    }
    /**
     * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    async removeFilteredGroupingPolicy(fieldIndex, ...fieldValues) {
        return this.removeFilteredNamedGroupingPolicy('g', fieldIndex, ...fieldValues);
    }
    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    async removeNamedGroupingPolicy(ptype, ...params) {
        await this.lock.acquireAsync();
        return super.removeNamedGroupingPolicy(ptype, ...params).finally(() => this.lock.release());
    }
    /**
     * removeFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    async removeFilteredNamedGroupingPolicy(ptype, fieldIndex, ...fieldValues) {
        await this.lock.acquireAsync();
        return super.removeFilteredNamedGroupingPolicy(ptype, fieldIndex, ...fieldValues).finally(() => this.lock.release());
    }
    /**
     * add matching function to RoleManager by ptype
     * @param ptype g
     * @param fn the function will be added
     */
    async addNamedMatchingFunc(ptype, fn) {
        await this.lock.acquireAsync();
        return super.addNamedMatchingFunc(ptype, fn).finally(() => this.lock.release());
    }
    /**
     * add domain matching function to RoleManager by ptype
     * @param ptype g
     * @param fn the function will be added
     */
    async addNamedDomainMatchingFunc(ptype, fn) {
        await this.lock.acquireAsync();
        return super.addNamedDomainMatchingFunc(ptype, fn).finally(() => {
            this.lock.release();
        });
    }
}
// newSyncedEnforcer creates a synchronized enforcer via file or DB.
export async function newSyncedEnforcer(...params) {
    return newEnforcerWithClass(SyncedEnforcer, ...params);
}
