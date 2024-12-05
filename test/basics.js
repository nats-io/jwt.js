/*
 * Copyright 2022-2024 The NATS Authors
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
const { describe, it } = require("node:test");
const assert = require("node:assert").strict;

const {
  createAccount,
  encodeAccount,
  createCurve,
  decode,
  Types,
  Algorithms,
  isOperator,
  isAccount,
  isUser,
  isActivation,
  isGeneric,
  version,
  Base64UrlCodec,
  fromSeed,
} = require("../lib/mod.js");

function parseTable(s) {
  const lines = s.split("\n");
  // remove separator lines and header boxes
  const rows = lines.filter((line, idx) => {
    return !(idx < 2 || line.startsWith("+") || line.length === 0);
  });
  return rows.map((row) => {
    if (!row.startsWith("|") || !row.endsWith("|")) {
      throw new Error(`unexpected row data "${row}"`);
    }
    let fields = row.split("|");
    fields = fields.slice(1, fields.length - 1);
    return fields.map((v) => v.trim());
  });
}
describe(
  "basics",
  { timeout: 20_000, forceExit: true, concurrency: true },
  () => {
    it("parse table", () => {
      const table =
        `+---------------------------------------------------------------------------------------------------------------+
|                                                     Keys                                                      |
+-----------------------------+----------------------------------------------------------+-------------+--------+
| Entity                      | Key                                                      | Signing Key | Stored |
+-----------------------------+----------------------------------------------------------+-------------+--------+
| name_U80HBXY1E636R3QZ6KK1AQ | ODWPVMRX675TNBUERYNNFKT55BCUJ3TMNZMWVCAO3WZQGGI7HU4EY4ED |             |        |
|  A                          | ACFACYHVLD2I5R5E5R4U7UGOURWAUIWY4GGBN4NKFQXBUCDMADN5HJOE |             |        |
+-----------------------------+----------------------------------------------------------+-------------+--------+
`;
      const v = parseTable(table);
      assert.equal(v.length, 3);
      assert.equal(v[0][0], "Entity");
      assert.equal(v[0][1], "Key");
      assert.equal(v[0][2], "Signing Key");
      assert.equal(v[0][3], "Stored");
      assert.equal(v[1][0], "name_U80HBXY1E636R3QZ6KK1AQ");
      assert.equal(
        v[1][1],
        "ODWPVMRX675TNBUERYNNFKT55BCUJ3TMNZMWVCAO3WZQGGI7HU4EY4ED",
      );
      assert.equal(v[1][2], "");
      assert.equal(v[1][3], "");
      assert.equal(v[2][0], "A");
      assert.equal(
        v[2][1],
        "ACFACYHVLD2I5R5E5R4U7UGOURWAUIWY4GGBN4NKFQXBUCDMADN5HJOE",
      );
      assert.equal(v[2][2], "");
      assert.equal(v[2][3], "");
    });

    it("jwt - rejects bad chunks", () => {
      const jwt = `eyJhbGciOiJIUzI1NiIsInR`;

      assert.throws(() => {
        return decode(jwt);
      }, { message: /invalid jwt/ });
    });

    it("jwt - rejects bad algorithm", () => {
      const jwt =
        `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
      assert.throws(
        () => {
          return decode(jwt);
        },
        { message: /not a nats jwt/ },
      );
    });

    it("jwt - encodes/decodes v1", async () => {
      const akp = createAccount();
      const token = await encodeAccount("A", akp, {}, {
        algorithm: Algorithms.v1,
      });
      const ac = await decode(token);
      assert.equal(version(ac), 1);
      assert.notEqual(version(ac), 2);
      assert.ok(!isOperator(ac));
      assert.ok(isAccount(ac));
      assert.ok(!isUser(ac));
      assert.ok(!isGeneric(ac));
      assert.ok(!isActivation(ac));
      assert.equal(ac.type, Types.Account);
      assert.deepEqual(ac.nats, {});
    });

    it("jwt - rejects bad type", async () => {
      const jwt =
        `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;

      const chunks = jwt.split(".");
      chunks[0] = Base64UrlCodec.encode(
        JSON.stringify({ typ: "Foo", alg: "ed25519-nkey" }),
      );

      await assert.throws(
        () => {
          return decode(chunks.join("."));
        },
        { message: /not a nats jwt/ },
      );
    });

    it("jwt - rejects bad signature", async () => {
      const akp = createAccount();
      const token = await encodeAccount("A", akp);
      const chunks = token.split(".");
      chunks[2] = chunks[2].split("").reverse().join("");
      await assert.throws(
        () => {
          return decode(chunks.join("."));
        },
        {
          message: /sig verification failed/,
        },
      );
    });

    it("curve parses", () => {
      const ckp = createCurve();
      const pk = ckp.getPublicKey();
      assert.ok(pk.startsWith("X"));
      const skp = new TextDecoder().decode(ckp.getSeed());
      assert.ok(skp.startsWith("SX"));

      const xkp = fromSeed(ckp.getSeed());
      const msg = xkp.seal(new TextEncoder().encode("hello"), pk);

      const d = xkp.open(msg, pk);
      assert.ok(d);
      assert.equal(new TextDecoder().decode(d), "hello");
    });
  },
);
