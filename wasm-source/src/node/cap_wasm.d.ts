/* tslint:disable */
/* eslint-disable */
/**
 * Solve an ASCII hexadecimal hash prefix of at most 16 digits (case-insensitive).
 * An empty prefix matches any hash. Invalid targets panic (trap in Wasm)
 * before searching; they never return a nonce that looks like a solution.
 */
export function solve_pow(salt: string, target: string): bigint;
