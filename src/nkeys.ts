import * as nkeys from "https://raw.githubusercontent.com/nats-io/nkeys.js/v1.0.0-9/modules/esm/mod.ts";

const createOperator = nkeys.createOperator;
const createAccount = nkeys.createAccount;
const createUser = nkeys.createUser;
const fromSeed = nkeys.fromSeed;
const fromPublic = nkeys.fromPublic;
export { createAccount, createOperator, createUser, fromPublic, fromSeed };

export interface KeyPair {
  getPublicKey(): string;
  getPrivateKey(): Uint8Array;
  getSeed(): Uint8Array;
  sign(input: Uint8Array): Uint8Array;
  verify(input: Uint8Array, sig: Uint8Array): boolean;
  clear(): void;
}
