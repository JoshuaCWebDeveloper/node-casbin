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
import { InternalEnforcer } from './internalEnforcer';
/**
 * ManagementEnforcer = InternalEnforcer + Management API.
 */
export class ManagementEnforcer extends InternalEnforcer {
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
        return this.model.getValuesForFieldInPolicy('p', ptype, 0);
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
        return this.model.getValuesForFieldInPolicy('p', ptype, 1);
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
        return this.model.getValuesForFieldInPolicy('p', ptype, 2);
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
        return this.model.getValuesForFieldInPolicy('g', ptype, 1);
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
        return this.model.getPolicy('p', ptype);
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
        return this.model.getFilteredPolicy('p', ptype, fieldIndex, ...fieldValues);
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
        return this.model.getPolicy('g', ptype);
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
        return this.model.getFilteredPolicy('g', ptype, fieldIndex, ...fieldValues);
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
        return this.model.hasPolicy('p', ptype, params);
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
     * addPolicies adds authorization rules to the current policy.
     * If the rule already exists, the function returns false and the rules will not be added.
     * Otherwise the function returns true by adding the new rules.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    async addPolicies(rules) {
        return this.addNamedPolicies('p', rules);
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
        return this.addPolicyInternal('p', ptype, params);
    }
    /**
     * addNamedPolicies adds authorization rules to the current named policy.
     * If the rule already exists, the function returns false and the rules will not be added.
     * Otherwise the function returns true by adding the new rules.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param rules the "p" policy rules.
     * @return succeeds or not.
     */
    async addNamedPolicies(ptype, rules) {
        return this.addPoliciesInternal('p', ptype, rules);
    }
    /**
     * updatePolicy updates an authorization rule from the current policy.
     * If the rule not exists, the function returns false.
     * Otherwise the function returns true by changing it to the new rule.
     *
     * @return succeeds or not.
     * @param oldRule the policy will be remove
     * @param newRule the policy will be added
     */
    async updatePolicy(oldRule, newRule) {
        return this.updateNamedPolicy('p', oldRule, newRule);
    }
    /**
     * updateNamedPolicy updates an authorization rule from the current named policy.
     * If the rule not exists, the function returns false.
     * Otherwise the function returns true by changing it to the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param oldRule the policy rule will be remove
     * @param newRule the policy rule will be added
     * @return succeeds or not.
     */
    async updateNamedPolicy(ptype, oldRule, newRule) {
        return this.updatePolicyInternal('p', ptype, oldRule, newRule);
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
     * removePolicies removes an authorization rules from the current policy.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    async removePolicies(rules) {
        return this.removeNamedPolicies('p', rules);
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
        return this.removePolicyInternal('p', ptype, params);
    }
    /**
     * removeNamedPolicies removes authorization rules from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param rules the "p" policy rules.
     * @return succeeds or not.
     */
    async removeNamedPolicies(ptype, rules) {
        return this.removePoliciesInternal('p', ptype, rules);
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
        return this.removeFilteredPolicyInternal('p', ptype, fieldIndex, fieldValues);
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
        return this.model.hasPolicy('g', ptype, params);
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
     * addGroupingPolicies adds a role inheritance rules to the current policy.
     * If the rule already exists, the function returns false and the rules will not be added.
     * Otherwise the function returns true by adding the new rules.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    async addGroupingPolicies(rules) {
        return this.addNamedGroupingPolicies('g', rules);
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
        return this.addPolicyInternal('g', ptype, params);
    }
    /**
     * addNamedGroupingPolicies adds named role inheritance rules to the current policy.
     * If the rule already exists, the function returns false and the rules will not be added.
     * Otherwise the function returns true by adding the new rules.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rule.
     * @return succeeds or not.
     */
    async addNamedGroupingPolicies(ptype, rules) {
        return this.addPoliciesInternal('g', ptype, rules);
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
     * removeGroupingPolicies removes role inheritance rules from the current policy.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    async removeGroupingPolicies(rules) {
        return this.removeNamedGroupingPolicies('g', rules);
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
        return this.removePolicyInternal('g', ptype, params);
    }
    /**
     * removeNamedGroupingPolicies removes role inheritance rules from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    async removeNamedGroupingPolicies(ptype, rules) {
        return this.removePoliciesInternal('g', ptype, rules);
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
        return this.removeFilteredPolicyInternal('g', ptype, fieldIndex, fieldValues);
    }
    /**
     * addFunction adds a customized function.
     * @param name custom function name
     * @param func function
     */
    async addFunction(name, func) {
        this.fm.addFunction(name, func);
    }
}
