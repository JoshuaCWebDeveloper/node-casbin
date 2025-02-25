import * as rbac from '../rbac';
import { PolicyOp } from './model';
export declare class Assertion {
    key: string;
    value: string;
    tokens: string[];
    policy: string[][];
    rm: rbac.RoleManager;
    /**
     * constructor is the constructor for Assertion.
     */
    constructor();
    buildIncrementalRoleLinks(rm: rbac.RoleManager, op: PolicyOp, rules: string[][]): Promise<void>;
    buildRoleLinks(rm: rbac.RoleManager): Promise<void>;
}
