/*
 * Copyright 2024 Synadia Communications, Inc
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { createCurve } from "../src/mod.ts";

import { assert, assertEquals, assertExists } from "@std/assert";
import { fromSeed } from "@nats-io/nkeys";

Deno.test("curve parses", () => {
  const ckp = createCurve();
  const pk = ckp.getPublicKey();
  assert(pk.startsWith("X"));
  const skp = new TextDecoder().decode(ckp.getSeed());
  assert(skp.startsWith("SX"));

  const xkp = fromSeed(ckp.getSeed());
  const msg = xkp.seal(new TextEncoder().encode("hello"), pk);

  const d = xkp.open(msg, pk);
  assertExists(d);
  assertEquals(new TextDecoder().decode(d), "hello");
});
