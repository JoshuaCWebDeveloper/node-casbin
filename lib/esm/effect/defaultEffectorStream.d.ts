import { EffectorStream } from './effectorStream';
import { Effect } from './effector';
/**
 * DefaultEffectorStream is the default implementation of EffectorStream.
 */
export declare class DefaultEffectorStream implements EffectorStream {
    private done;
    private res;
    private readonly expr;
    constructor(expr: string);
    current(): boolean;
    pushEffect(eft: Effect): [boolean, boolean];
}
