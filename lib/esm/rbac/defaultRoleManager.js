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
import { getLogger, logPrint } from '../log';
// DEFAULT_DOMAIN defines the default domain space.
const DEFAULT_DOMAIN = 'casbin::default';
// loadOrDefault returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
function loadOrDefault(map, key, value) {
    const read = map.get(key);
    if (read === undefined) {
        map.set(key, value);
        return value;
    }
    return read;
}
/**
 * Role represents the data structure for a role in RBAC.
 */
class Role {
    constructor(name) {
        this.name = name;
        this.roles = [];
    }
    addRole(role) {
        if (this.roles.some((n) => n.name === role.name)) {
            return;
        }
        this.roles.push(role);
    }
    deleteRole(role) {
        this.roles = this.roles.filter((n) => n.name !== role.name);
    }
    hasRole(name, hierarchyLevel) {
        if (this.name === name) {
            return true;
        }
        if (hierarchyLevel <= 0) {
            return false;
        }
        for (const role of this.roles) {
            if (role.hasRole(name, hierarchyLevel - 1)) {
                return true;
            }
        }
        return false;
    }
    hasDirectRole(name) {
        return this.roles.some((n) => n.name === name);
    }
    toString() {
        return this.name + this.roles.join(', ');
    }
    getRoles() {
        return this.roles.map((n) => n.name);
    }
}
class Roles extends Map {
    constructor() {
        super();
    }
    hasRole(name, matchingFunc) {
        let ok = false;
        if (matchingFunc) {
            this.forEach((value, key) => {
                if (matchingFunc(name, key)) {
                    ok = true;
                }
            });
        }
        else {
            return this.has(name);
        }
        return ok;
    }
    createRole(name, matchingFunc) {
        const role = loadOrDefault(this, name, new Role(name));
        if (matchingFunc) {
            this.forEach((value, key) => {
                if (matchingFunc(name, key) && name !== key) {
                    // Add new role to matching role
                    const role1 = loadOrDefault(this, key, new Role(key));
                    role.addRole(role1);
                }
            });
        }
        return role;
    }
}
// RoleManager provides a default implementation for the RoleManager interface
export class DefaultRoleManager {
    /**
     * DefaultRoleManager is the constructor for creating an instance of the
     * default RoleManager implementation.
     *
     * @param maxHierarchyLevel the maximized allowed RBAC hierarchy level.
     */
    constructor(maxHierarchyLevel) {
        this.hasPattern = false;
        this.hasDomainPattern = false;
        this.allDomains = new Map();
        this.allDomains.set(DEFAULT_DOMAIN, new Roles());
        this.maxHierarchyLevel = maxHierarchyLevel;
    }
    /**
     * addMatchingFunc support use pattern in g
     * @param name name
     * @param fn matching function
     * @deprecated
     */
    async addMatchingFunc(name, fn) {
        this.hasPattern = true;
        if (typeof name === 'string' && fn) {
            this.matchingFunc = fn;
        }
        else if (typeof name === 'function') {
            this.matchingFunc = name;
        }
        else {
            throw new Error('error: domain should be 1 parameter');
        }
    }
    /**
     * addDomainMatchingFunc support use domain pattern in g
     * @param fn domain matching function
     * ```
     */
    async addDomainMatchingFunc(fn) {
        this.hasDomainPattern = true;
        this.domainMatchingFunc = fn;
    }
    generateTempRoles(domain) {
        loadOrDefault(this.allDomains, domain, new Roles());
        const patternDomain = new Set([domain]);
        if (this.hasDomainPattern) {
            this.allDomains.forEach((value, key) => {
                if (this.domainMatchingFunc(domain, key)) {
                    patternDomain.add(key);
                }
            });
        }
        const allRoles = new Roles();
        patternDomain.forEach((domain) => {
            loadOrDefault(this.allDomains, domain, new Roles()).forEach((value, key) => {
                const role1 = allRoles.createRole(value.name, this.matchingFunc);
                value.getRoles().forEach((n) => {
                    role1.addRole(allRoles.createRole(n, this.matchingFunc));
                });
            });
        });
        return allRoles;
    }
    /**
     * addLink adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    async addLink(name1, name2, ...domain) {
        if (domain.length === 0) {
            domain = [DEFAULT_DOMAIN];
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        const allRoles = loadOrDefault(this.allDomains, domain[0], new Roles());
        const role1 = loadOrDefault(allRoles, name1, new Role(name1));
        const role2 = loadOrDefault(allRoles, name2, new Role(name2));
        role1.addRole(role2);
    }
    /**
     * clear clears all stored data and resets the role manager to the initial state.
     */
    async clear() {
        this.allDomains = new Map();
        this.allDomains.set(DEFAULT_DOMAIN, new Roles());
    }
    /**
     * deleteLink deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     */
    async deleteLink(name1, name2, ...domain) {
        if (domain.length === 0) {
            domain = [DEFAULT_DOMAIN];
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        const allRoles = loadOrDefault(this.allDomains, domain[0], new Roles());
        if (!allRoles.has(name1) || !allRoles.has(name2)) {
            return;
        }
        const role1 = loadOrDefault(allRoles, name1, new Role(name1));
        const role2 = loadOrDefault(allRoles, name2, new Role(name2));
        role1.deleteRole(role2);
    }
    /**
     * hasLink determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     */
    async hasLink(name1, name2, ...domain) {
        if (domain.length === 0) {
            domain = [DEFAULT_DOMAIN];
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        if (name1 === name2) {
            return true;
        }
        let allRoles;
        if (this.hasPattern || this.hasDomainPattern) {
            allRoles = this.generateTempRoles(domain[0]);
        }
        else {
            allRoles = loadOrDefault(this.allDomains, domain[0], new Roles());
        }
        if (!allRoles.hasRole(name1, this.matchingFunc) || !allRoles.hasRole(name2, this.matchingFunc)) {
            return false;
        }
        const role1 = allRoles.createRole(name1, this.matchingFunc);
        return role1.hasRole(name2, this.maxHierarchyLevel);
    }
    /**
     * getRoles gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     */
    async getRoles(name, ...domain) {
        if (domain.length === 0) {
            domain = [DEFAULT_DOMAIN];
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        let allRoles;
        if (this.hasPattern || this.hasDomainPattern) {
            allRoles = this.generateTempRoles(domain[0]);
        }
        else {
            allRoles = loadOrDefault(this.allDomains, domain[0], new Roles());
        }
        if (!allRoles.hasRole(name, this.matchingFunc)) {
            return [];
        }
        return allRoles.createRole(name, this.matchingFunc).getRoles();
    }
    /**
     * getUsers gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     */
    async getUsers(name, ...domain) {
        if (domain.length === 0) {
            domain = [DEFAULT_DOMAIN];
        }
        else if (domain.length > 1) {
            throw new Error('error: domain should be 1 parameter');
        }
        let allRoles;
        if (this.hasPattern || this.hasDomainPattern) {
            allRoles = this.generateTempRoles(domain[0]);
        }
        else {
            allRoles = loadOrDefault(this.allDomains, domain[0], new Roles());
        }
        if (!allRoles.hasRole(name, this.matchingFunc)) {
            return [];
        }
        return [...allRoles.values()].filter((n) => n.hasDirectRole(name)).map((n) => n.name);
    }
    /**
     * printRoles prints all the roles to log.
     */
    async printRoles() {
        if (getLogger().isEnable()) {
            [...this.allDomains.values()].forEach((n) => {
                logPrint(n.toString());
            });
        }
    }
}
