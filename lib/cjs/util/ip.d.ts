/// <reference types="node" />
import { Buffer } from 'buffer';
export declare const ip: {
    toBuffer: (ip: string, buff?: Buffer | undefined, offset?: number | undefined) => Buffer;
    toString: (buff: Buffer, offset?: number | undefined, length?: number | undefined) => string;
    isV4Format: (ip: string) => boolean;
    isV6Format: (ip: string) => boolean;
    fromPrefixLen: (prefixlen: number, family?: string | undefined) => string;
    mask: (addr: string, mask: string) => string;
    subnet: (addr: string, mask: string) => any;
    cidrSubnet: (cidrString: string) => any;
    isEqual: (a: string, b: string) => boolean;
    toLong: (ip: string) => number;
    fromLong: (ipl: number) => string;
};
