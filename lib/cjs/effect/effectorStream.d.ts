import { Effect } from './effector';
export interface EffectorStream {
    current(): boolean;
    pushEffect(eft: Effect): [boolean, boolean];
}
