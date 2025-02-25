import { RoleManager } from './roleManager';
export declare type MatchingFunc = (arg1: string, arg2: string) => boolean;
export declare class DefaultRoleManager implements RoleManager {
    private allDomains;
    private maxHierarchyLevel;
    private hasPattern;
    private hasDomainPattern;
    private matchingFunc;
    private domainMatchingFunc;
    /**
     * DefaultRoleManager is the constructor for creating an instance of the
     * default RoleManager implementation.
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     */
    constructor(maxHierarchyLevel: number);
    /**
     * addMatchingFunc support use pattern in g
     * @param name name
     * @param fn matching function
     * @deprecated
     */
    addMatchingFunc(name: string, fn: MatchingFunc): Promise<void>;
    /**
     * addMatchingFunc support use pattern in g
     * @param fn matching function
     */
    addMatchingFunc(fn: MatchingFunc): Promise<void>;
    /**
     * addDomainMatchingFunc support use domain pattern in g
     * @param fn domain matching function
     * ```
     */
    addDomainMatchingFunc(fn: MatchingFunc): Promise<void>;
    private generateTempRoles;
    /**
     * addLink adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    addLink(name1: string, name2: string, ...domain: string[]): Promise<void>;
    /**
     * clear clears all stored data and resets the role manager to the initial state.
     */
    clear(): Promise<void>;
    /**
     * deleteLink deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     */
    deleteLink(name1: string, name2: string, ...domain: string[]): Promise<void>;
    /**
     * hasLink determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    hasLink(name1: string, name2: string, ...domain: string[]): Promise<boolean>;
    /**
     * getRoles gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     */
    getRoles(name: string, ...domain: string[]): Promise<string[]>;
    /**
     * getUsers gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     */
    getUsers(name: string, ...domain: string[]): Promise<string[]>;
    /**
     * printRoles prints all the roles to log.
     */
    printRoles(): Promise<void>;
}
