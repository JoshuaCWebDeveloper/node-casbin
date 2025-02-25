import { ManagementEnforcer } from './managementEnforcer';
import { Model } from './model';
import { Adapter } from './persist';
/**
 * Enforcer = ManagementEnforcer + RBAC API.
 */
export declare class Enforcer extends ManagementEnforcer {
    /**
     * initWithFile initializes an enforcer with a model file and a policy file.
     * @param modelPath model file path
     * @param policyPath policy file path
     * @param lazyLoad lazyLoad whether to load policy at initial time
     */
    initWithFile(modelPath: string, policyPath: string, lazyLoad?: boolean): Promise<void>;
    /**
     * initWithFile initializes an enforcer with a model file and a policy file.
     * @param modelPath model file path
     * @param policyString policy CSV string
     * @param lazyLoad whether to load policy at initial time
     */
    initWithString(modelPath: string, policyString: string, lazyLoad?: boolean): Promise<void>;
    /**
     * initWithAdapter initializes an enforcer with a database adapter.
     * @param modelPath model file path
     * @param adapter current adapter instance
     * @param lazyLoad whether to load policy at initial time
     */
    initWithAdapter(modelPath: string, adapter: Adapter, lazyLoad?: boolean): Promise<void>;
    /**
     * initWithModelAndAdapter initializes an enforcer with a model and a database adapter.
     * @param m model instance
     * @param adapter current adapter instance
     * @param lazyLoad whether to load policy at initial time
     */
    initWithModelAndAdapter(m: Model, adapter?: Adapter, lazyLoad?: boolean): Promise<void>;
    /**
     * getRolesForUser gets the roles that a user has.
     *
     * @param name the user.
     * @param domain the domain.
     * @return the roles that the user has.
     */
    getRolesForUser(name: string, domain?: string): Promise<string[]>;
    /**
     * getUsersForRole gets the users that has a role.
     *
     * @param name the role.
     * @param domain the domain.
     * @return the users that has the role.
     */
    getUsersForRole(name: string, domain?: string): Promise<string[]>;
    /**
     * hasRoleForUser determines whether a user has a role.
     *
     * @param name the user.
     * @param role the role.
     * @param domain the domain.
     * @return whether the user has the role.
     */
    hasRoleForUser(name: string, role: string, domain?: string): Promise<boolean>;
    /**
     * addRoleForUser adds a role for a user.
     * Returns false if the user already has the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    addRoleForUser(user: string, role: string, domain?: string): Promise<boolean>;
    /**
     * deleteRoleForUser deletes a role for a user.
     * Returns false if the user does not have the role (aka not affected).
     *
     * @param user the user.
     * @param role the role.
     * @param domain the domain.
     * @return succeeds or not.
     */
    deleteRoleForUser(user: string, role: string, domain?: string): Promise<boolean>;
    /**
     * deleteRolesForUser deletes all roles for a user.
     * Returns false if the user does not have any roles (aka not affected).
     *
     * @param user the user.
     * @param domain the domain.
     * @return succeeds or not.
     */
    deleteRolesForUser(user: string, domain?: string): Promise<boolean>;
    /**
     * deleteUser deletes a user.
     * Returns false if the user does not exist (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    deleteUser(user: string): Promise<boolean>;
    /**
     * deleteRole deletes a role.
     * Returns false if the role does not exist (aka not affected).
     *
     * @param role the role.
     * @return succeeds or not.
     */
    deleteRole(role: string): Promise<boolean>;
    /**
     * deletePermission deletes a permission.
     * Returns false if the permission does not exist (aka not affected).
     *
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    deletePermission(...permission: string[]): Promise<boolean>;
    /**
     * addPermissionForUser adds a permission for a user or role.
     * Returns false if the user or role already has the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    addPermissionForUser(user: string, ...permission: string[]): Promise<boolean>;
    /**
     * deletePermissionForUser deletes a permission for a user or role.
     * Returns false if the user or role does not have the permission (aka not affected).
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return succeeds or not.
     */
    deletePermissionForUser(user: string, ...permission: string[]): Promise<boolean>;
    /**
     * deletePermissionsForUser deletes permissions for a user or role.
     * Returns false if the user or role does not have any permissions (aka not affected).
     *
     * @param user the user.
     * @return succeeds or not.
     */
    deletePermissionsForUser(user: string): Promise<boolean>;
    /**
     * getPermissionsForUser gets permissions for a user or role.
     *
     * @param user the user.
     * @return the permissions, a permission is usually like (obj, act). It is actually the rule without the subject.
     */
    getPermissionsForUser(user: string): Promise<string[][]>;
    /**
     * hasPermissionForUser determines whether a user has a permission.
     *
     * @param user the user.
     * @param permission the permission, usually be (obj, act). It is actually the rule without the subject.
     * @return whether the user has the permission.
     */
    hasPermissionForUser(user: string, ...permission: string[]): Promise<boolean>;
    /**
     * getImplicitRolesForUser gets implicit roles that a user has.
     * Compared to getRolesForUser(), this function retrieves indirect roles besides direct roles.
     * For example:
     * g, alice, role:admin
     * g, role:admin, role:user
     *
     * getRolesForUser("alice") can only get: ["role:admin"].
     * But getImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
     */
    getImplicitRolesForUser(name: string, ...domain: string[]): Promise<string[]>;
    /**
     * getImplicitPermissionsForUser gets implicit permissions for a user or role.
     * Compared to getPermissionsForUser(), this function retrieves permissions for inherited roles.
     * For example:
     * p, admin, data1, read
     * p, alice, data2, read
     * g, alice, admin
     *
     * getPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
     * But getImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
     */
    getImplicitPermissionsForUser(user: string, ...domain: string[]): Promise<string[][]>;
    /**
     * getImplicitUsersForPermission gets implicit users for a permission.
     * For example:
     * p, admin, data1, read
     * p, bob, data1, read
     * g, alice, admin
     *
     * getImplicitUsersForPermission("data1", "read") will get: ["alice", "bob"].
     * Note: only users will be returned, roles (2nd arg in "g") will be excluded.
     */
    getImplicitUsersForPermission(...permission: string[]): Promise<string[]>;
}
export declare function newEnforcerWithClass<T extends Enforcer>(enforcer: new () => T, ...params: any[]): Promise<T>;
/**
 * newEnforcer creates an enforcer via file or DB.
 *
 * File:
 * ```js
 * const e = new Enforcer('path/to/basic_model.conf', 'path/to/basic_policy.csv');
 * ```
 *
 * MySQL DB:
 * ```js
 * const a = new MySQLAdapter('mysql', 'mysql_username:mysql_password@tcp(127.0.0.1:3306)/');
 * const e = new Enforcer('path/to/basic_model.conf', a);
 * ```
 *
 * @param params
 */
export declare function newEnforcer(...params: any[]): Promise<Enforcer>;
