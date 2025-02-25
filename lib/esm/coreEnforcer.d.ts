import { Effector } from './effect';
import { FunctionMap, Model, PolicyOp } from './model';
import { Adapter, FilteredAdapter, Watcher, BatchAdapter, UpdatableAdapter } from './persist';
import { RoleManager } from './rbac';
import { MatchingFunc } from './rbac';
/**
 * CoreEnforcer defines the core functionality of an enforcer.
 */
export declare class CoreEnforcer {
    protected modelPath: string;
    protected model: Model;
    protected fm: FunctionMap;
    protected eft: Effector;
    private matcherMap;
    protected adapter: UpdatableAdapter | FilteredAdapter | Adapter | BatchAdapter;
    protected watcher: Watcher | null;
    protected rmMap: Map<string, RoleManager>;
    protected enabled: boolean;
    protected autoSave: boolean;
    protected autoBuildRoleLinks: boolean;
    protected autoNotifyWatcher: boolean;
    private getExpression;
    /**
     * loadModel reloads the model from the model CONF file.
     * Because the policy is attached to a model,
     * so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
     */
    loadModel(): void;
    /**
     * getModel gets the current model.
     *
     * @return the model of the enforcer.
     */
    getModel(): Model;
    /**
     * setModel sets the current model.
     *
     * @param m the model.
     */
    setModel(m: Model): void;
    /**
     * getAdapter gets the current adapter.
     *
     * @return the adapter of the enforcer.
     */
    getAdapter(): Adapter;
    /**
     * setAdapter sets the current adapter.
     *
     * @param adapter the adapter.
     */
    setAdapter(adapter: Adapter): void;
    /**
     * setWatcher sets the current watcher.
     *
     * @param watcher the watcher.
     */
    setWatcher(watcher: Watcher): void;
    /**
     * setRoleManager sets the current role manager.
     *
     * @param rm the role manager.
     */
    setRoleManager(rm: RoleManager): void;
    /**
     * getRoleManager gets the current role manager.
     */
    getRoleManager(): RoleManager;
    /**
     * getNamedRoleManager gets role manager by name.
     */
    getNamedRoleManager(name: string): RoleManager | undefined;
    /**
     * setEffector sets the current effector.
     *
     * @param eft the effector.
     */
    setEffector(eft: Effector): void;
    /**
     * clearPolicy clears all policy.
     */
    clearPolicy(): void;
    initRmMap(): void;
    sortPolicies(): void;
    /**
     * loadPolicy reloads the policy from file/database.
     */
    loadPolicy(): Promise<void>;
    /**
     * loadFilteredPolicy reloads a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be loaded.
     */
    loadFilteredPolicy(filter: any): Promise<boolean>;
    /**
     * LoadIncrementalFilteredPolicy append a filtered policy from file/database.
     *
     * @param filter the filter used to specify which type of policy should be appended.
     */
    loadIncrementalFilteredPolicy(filter: any): Promise<boolean>;
    /**
     * isFiltered returns true if the loaded policy has been filtered.
     *
     * @return if the loaded policy has been filtered.
     */
    isFiltered(): boolean;
    /**
     * savePolicy saves the current policy (usually after changed with
     * Casbin API) back to file/database.
     */
    savePolicy(): Promise<boolean>;
    /**
     * enableEnforce changes the enforcing state of Casbin, when Casbin is
     * disabled, all access will be allowed by the enforce() function.
     *
     * @param enable whether to enable the enforcer.
     */
    enableEnforce(enable: boolean): void;
    /**
     * enableLog changes whether to print Casbin log to the standard output.
     *
     * @param enable whether to enable Casbin's log.
     */
    enableLog(enable: boolean): void;
    /**
     * enableAutoSave controls whether to save a policy rule automatically to
     * the adapter when it is added or removed.
     *
     * @param autoSave whether to enable the AutoSave feature.
     */
    enableAutoSave(autoSave: boolean): void;
    /**
     * enableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
     * @param enable whether to enable the AutoNotifyWatcher feature.
     */
    enableAutoNotifyWatcher(enable: boolean): void;
    /**
     * enableAutoBuildRoleLinks controls whether to save a policy rule
     * automatically to the adapter when it is added or removed.
     *
     * @param autoBuildRoleLinks whether to automatically build the role links.
     */
    enableAutoBuildRoleLinks(autoBuildRoleLinks: boolean): void;
    /**
     * add matching function to RoleManager by ptype
     * @param ptype g
     * @param fn the function will be added
     */
    addNamedMatchingFunc(ptype: string, fn: MatchingFunc): Promise<void>;
    /**
     * add domain matching function to RoleManager by ptype
     * @param ptype g
     * @param fn the function will be added
     */
    addNamedDomainMatchingFunc(ptype: string, fn: MatchingFunc): Promise<void>;
    /**
     * buildRoleLinks manually rebuild the role inheritance relations.
     */
    buildRoleLinks(): Promise<void>;
    /**
     * buildIncrementalRoleLinks provides incremental build the role inheritance relations.
     * @param op policy operation
     * @param ptype g
     * @param rules policies
     */
    buildIncrementalRoleLinks(op: PolicyOp, ptype: string, rules: string[][]): Promise<void>;
    protected buildRoleLinksInternal(): Promise<void>;
    private privateEnforce;
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
    enforceSync(...rvals: any[]): boolean;
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
    enforceExSync(...rvals: any[]): [boolean, string[]];
    /**
     * Same as enforceSync. To be removed.
     */
    enforceWithSyncCompile(...rvals: any[]): boolean;
    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request.
     */
    enforce(...rvals: any[]): Promise<boolean>;
    /**
     * enforce decides whether a "subject" can access a "object" with
     * the operation "action", input parameters are usually: (sub, obj, act).
     *
     * @param rvals the request needs to be mediated, usually an array
     *              of strings, can be class instances if ABAC is used.
     * @return whether to allow the request and the reason rule.
     */
    enforceEx(...rvals: any[]): Promise<[boolean, string[]]>;
}
