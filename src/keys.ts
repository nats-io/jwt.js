// Copyright 2021-2022 The NATS Authors
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

import { fromPublic, fromSeed, KeyPair } from "./nkeys.ts";

export type Key = string | Uint8Array | KeyPair;

function parseKey(v: string | Uint8Array): KeyPair {
  if (v instanceof Uint8Array) {
    v = new TextDecoder().decode(v);
  }
  if (v.charAt(0) === "S") {
    return fromSeed(new TextEncoder().encode(v));
  }
  return fromPublic(v);
}

export function checkKey(
  v: Key,
  type: string | string[] = "",
  seed = false,
): KeyPair {
  const kp: KeyPair = (typeof v === "string" || v instanceof Uint8Array)
    ? parseKey(v)
    : v;
  const k = kp.getPublicKey();

  const types = [];
  if (!Array.isArray(type)) {
    if (type !== "") {
      types.push(type);
    }
  } else {
    types.push(...type);
  }
  if (type.length > 0 && types.indexOf(k.charAt(0)) === -1) {
    throw new Error(`unexpected type ${k.charAt(0)} - wanted ${types}`);
  }
  if (seed) {
    // throws
    kp.getPrivateKey();
  }
  return kp;
}
