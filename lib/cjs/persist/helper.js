"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Helper = void 0;
const parse = require("csv-parse/lib/sync");
class Helper {
    static loadPolicyLine(line, model) {
        if (!line || line.trimStart().charAt(0) === '#') {
            return;
        }
        const tokens = parse(line, {
            delimiter: ',',
            skip_empty_lines: true,
            trim: true,
        });
        if (!tokens || !tokens[0]) {
            return;
        }
        const key = tokens[0][0];
        const sec = key.substring(0, 1);
        const item = model.model.get(sec);
        if (!item) {
            return;
        }
        const policy = item.get(key);
        if (!policy) {
            return;
        }
        policy.policy.push(tokens[0].slice(1));
    }
}
exports.Helper = Helper;
