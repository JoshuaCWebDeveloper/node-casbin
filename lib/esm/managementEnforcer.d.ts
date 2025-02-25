import { InternalEnforcer } from './internalEnforcer';
import { MatchingFunction } from './model';
/**
 * ManagementEnforcer = InternalEnforcer + Management API.
 */
export declare class ManagementEnforcer extends InternalEnforcer {
    /**
     * getAllSubjects gets the list of subjects that show up in the current policy.
     *
     * @return all the subjects in "p" policy rules. It actually collects the
     *         0-index elements of "p" policy rules. So make sure your subject
     *         is the 0-index element, like (sub, obj, act). Duplicates are removed.
     */
    getAllSubjects(): Promise<string[]>;
    /**
     * getAllNamedSubjects gets the list of subjects that show up in the currentnamed policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the subjects in policy rules of the ptype type. It actually
     *         collects the 0-index elements of the policy rules. So make sure
     *         your subject is the 0-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllNamedSubjects(ptype: string): Promise<string[]>;
    /**
     * getAllObjects gets the list of objects that show up in the current policy.
     *
     * @return all the objects in "p" policy rules. It actually collects the
     *         1-index elements of "p" policy rules. So make sure your object
     *         is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllObjects(): Promise<string[]>;
    /**
     * getAllNamedObjects gets the list of objects that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the objects in policy rules of the ptype type. It actually
     *         collects the 1-index elements of the policy rules. So make sure
     *         your object is the 1-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllNamedObjects(ptype: string): Promise<string[]>;
    /**
     * getAllActions gets the list of actions that show up in the current policy.
     *
     * @return all the actions in "p" policy rules. It actually collects
     *         the 2-index elements of "p" policy rules. So make sure your action
     *         is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllActions(): Promise<string[]>;
    /**
     * GetAllNamedActions gets the list of actions that show up in the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return all the actions in policy rules of the ptype type. It actually
     *         collects the 2-index elements of the policy rules. So make sure
     *         your action is the 2-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllNamedActions(ptype: string): Promise<string[]>;
    /**
     * getAllRoles gets the list of roles that show up in the current policy.
     *
     * @return all the roles in "g" policy rules. It actually collects
     *         the 1-index elements of "g" policy rules. So make sure your
     *         role is the 1-index element, like (sub, role).
     *         Duplicates are removed.
     */
    getAllRoles(): Promise<string[]>;
    /**
     * getAllNamedRoles gets the list of roles that show up in the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return all the subjects in policy rules of the ptype type. It actually
     *         collects the 0-index elements of the policy rules. So make
     *         sure your subject is the 0-index element, like (sub, obj, act).
     *         Duplicates are removed.
     */
    getAllNamedRoles(ptype: string): Promise<string[]>;
    /**
     * getPolicy gets all the authorization rules in the policy.
     *
     * @return all the "p" policy rules.
     */
    getPolicy(): Promise<string[][]>;
    /**
     * getFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules.
     */
    getFilteredPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<string[][]>;
    /**
     * getNamedPolicy gets all the authorization rules in the named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @return the "p" policy rules of the specified ptype.
     */
    getNamedPolicy(ptype: string): Promise<string[][]>;
    /**
     * getFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "p" policy rules of the specified ptype.
     */
    getFilteredNamedPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<string[][]>;
    /**
     * getGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @return all the "g" policy rules.
     */
    getGroupingPolicy(): Promise<string[][]>;
    /**
     * getFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value "" means not to match this field.
     * @return the filtered "g" policy rules.
     */
    getFilteredGroupingPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<string[][]>;
    /**
     * getNamedGroupingPolicy gets all the role inheritance rules in the policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @return the "g" policy rules of the specified ptype.
     */
    getNamedGroupingPolicy(ptype: string): Promise<string[][]>;
    /**
     * getFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return the filtered "g" policy rules of the specified ptype.
     */
    getFilteredNamedGroupingPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<string[][]>;
    /**
     * hasPolicy determines whether an authorization rule exists.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return whether the rule exists.
     */
    hasPolicy(...params: string[]): Promise<boolean>;
    /**
     * hasNamedPolicy determines whether a named authorization rule exists.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return whether the rule exists.
     */
    hasNamedPolicy(ptype: string, ...params: string[]): Promise<boolean>;
    /**
     * addPolicy adds an authorization rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    addPolicy(...params: string[]): Promise<boolean>;
    /**
     * addPolicies adds authorization rules to the current policy.
     * If the rule already exists, the function returns false and the rules will not be added.
     * Otherwise the function returns true by adding the new rules.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    addPolicies(rules: string[][]): Promise<boolean>;
    /**
     * addNamedPolicy adds an authorization rule to the current named policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    addNamedPolicy(ptype: string, ...params: string[]): Promise<boolean>;
    /**
     * addNamedPolicies adds authorization rules to the current named policy.
     * If the rule already exists, the function returns false and the rules will not be added.
     * Otherwise the function returns true by adding the new rules.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param rules the "p" policy rules.
     * @return succeeds or not.
     */
    addNamedPolicies(ptype: string, rules: string[][]): Promise<boolean>;
    /**
     * updatePolicy updates an authorization rule from the current policy.
     * If the rule not exists, the function returns false.
     * Otherwise the function returns true by changing it to the new rule.
     *
     * @return succeeds or not.
     * @param oldRule the policy will be remove
     * @param newRule the policy will be added
     */
    updatePolicy(oldRule: string[], newRule: string[]): Promise<boolean>;
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
    updateNamedPolicy(ptype: string, oldRule: string[], newRule: string[]): Promise<boolean>;
    /**
     * removePolicy removes an authorization rule from the current policy.
     *
     * @param params the "p" policy rule, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    removePolicy(...params: string[]): Promise<boolean>;
    /**
     * removePolicies removes an authorization rules from the current policy.
     *
     * @param rules the "p" policy rules, ptype "p" is implicitly used.
     * @return succeeds or not.
     */
    removePolicies(rules: string[][]): Promise<boolean>;
    /**
     * removeFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    removeFilteredPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<boolean>;
    /**
     * removeNamedPolicy removes an authorization rule from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param params the "p" policy rule.
     * @return succeeds or not.
     */
    removeNamedPolicy(ptype: string, ...params: string[]): Promise<boolean>;
    /**
     * removeNamedPolicies removes authorization rules from the current named policy.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param rules the "p" policy rules.
     * @return succeeds or not.
     */
    removeNamedPolicies(ptype: string, rules: string[][]): Promise<boolean>;
    /**
     * removeFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "p", "p2", "p3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    removeFilteredNamedPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<boolean>;
    /**
     * hasGroupingPolicy determines whether a role inheritance rule exists.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return whether the rule exists.
     */
    hasGroupingPolicy(...params: string[]): Promise<boolean>;
    /**
     * hasNamedGroupingPolicy determines whether a named role inheritance rule exists.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return whether the rule exists.
     */
    hasNamedGroupingPolicy(ptype: string, ...params: string[]): Promise<boolean>;
    /**
     * addGroupingPolicy adds a role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    addGroupingPolicy(...params: string[]): Promise<boolean>;
    /**
     * addGroupingPolicies adds a role inheritance rules to the current policy.
     * If the rule already exists, the function returns false and the rules will not be added.
     * Otherwise the function returns true by adding the new rules.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    addGroupingPolicies(rules: string[][]): Promise<boolean>;
    /**
     * addNamedGroupingPolicy adds a named role inheritance rule to the current policy.
     * If the rule already exists, the function returns false and the rule will not be added.
     * Otherwise the function returns true by adding the new rule.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    addNamedGroupingPolicy(ptype: string, ...params: string[]): Promise<boolean>;
    /**
     * addNamedGroupingPolicies adds named role inheritance rules to the current policy.
     * If the rule already exists, the function returns false and the rules will not be added.
     * Otherwise the function returns true by adding the new rules.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rule.
     * @return succeeds or not.
     */
    addNamedGroupingPolicies(ptype: string, rules: string[][]): Promise<boolean>;
    /**
     * removeGroupingPolicy removes a role inheritance rule from the current policy.
     *
     * @param params the "g" policy rule, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    removeGroupingPolicy(...params: string[]): Promise<boolean>;
    /**
     * removeGroupingPolicies removes role inheritance rules from the current policy.
     *
     * @param rules the "g" policy rules, ptype "g" is implicitly used.
     * @return succeeds or not.
     */
    removeGroupingPolicies(rules: string[][]): Promise<boolean>;
    /**
     * removeFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
     *
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    removeFilteredGroupingPolicy(fieldIndex: number, ...fieldValues: string[]): Promise<boolean>;
    /**
     * removeNamedGroupingPolicy removes a role inheritance rule from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param params the "g" policy rule.
     * @return succeeds or not.
     */
    removeNamedGroupingPolicy(ptype: string, ...params: string[]): Promise<boolean>;
    /**
     * removeNamedGroupingPolicies removes role inheritance rules from the current named policy.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param rules the "g" policy rules.
     * @return succeeds or not.
     */
    removeNamedGroupingPolicies(ptype: string, rules: string[][]): Promise<boolean>;
    /**
     * removeFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
     *
     * @param ptype the policy type, can be "g", "g2", "g3", ..
     * @param fieldIndex the policy rule's start index to be matched.
     * @param fieldValues the field values to be matched, value ""
     *                    means not to match this field.
     * @return succeeds or not.
     */
    removeFilteredNamedGroupingPolicy(ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<boolean>;
    /**
     * addFunction adds a customized function.
     * @param name custom function name
     * @param func function
     */
    addFunction(name: string, func: MatchingFunction): Promise<void>;
}
