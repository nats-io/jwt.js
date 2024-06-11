// Copyright 2021-2024 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as nkeys from "jsr:@nats-io/nkeys";

const createOperator = nkeys.createOperator;
const createAccount = nkeys.createAccount;
const createUser = nkeys.createUser;
const createServer = nkeys.createServer;
const fromSeed = nkeys.fromSeed;
const fromPublic = nkeys.fromPublic;
export {
  createAccount,
  createOperator,
  createServer,
  createUser,
  fromPublic,
  fromSeed,
};

export interface KeyPair {
  getPublicKey(): string;
  getPrivateKey(): Uint8Array;
  getSeed(): Uint8Array;
  sign(input: Uint8Array): Uint8Array;
  verify(input: Uint8Array, sig: Uint8Array): boolean;
  clear(): void;
}
