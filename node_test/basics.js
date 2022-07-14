// Copyright 2022 The NATS Authors
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
const test = require("ava");
const {
  createAccount,
  encodeAccount,
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

test("parse table", (t) => {
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
  t.is(v.length, 3);
  t.is(v[0][0], "Entity");
  t.is(v[0][1], "Key");
  t.is(v[0][2], "Signing Key");
  t.is(v[0][3], "Stored");
  t.is(v[1][0], "name_U80HBXY1E636R3QZ6KK1AQ");
  t.is(
    v[1][1],
    "ODWPVMRX675TNBUERYNNFKT55BCUJ3TMNZMWVCAO3WZQGGI7HU4EY4ED",
  );
  t.is(v[1][2], "");
  t.is(v[1][3], "");
  t.is(v[2][0], "A");
  t.is(
    v[2][1],
    "ACFACYHVLD2I5R5E5R4U7UGOURWAUIWY4GGBN4NKFQXBUCDMADN5HJOE",
  );
  t.is(v[2][2], "");
  t.is(v[2][3], "");
});

test("jwt - rejects bad chunks", async (t) => {
  const jwt = `eyJhbGciOiJIUzI1NiIsInR`;

  t.plan(1);
  await t.throwsAsync(
    async () => {
      await decode(jwt);
    },
    { instanceOf: Error, message: /invalid jwt/ },
  );
});

test("jwt - rejects bad algorithm", async (t) => {
  const jwt =
    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
  t.plan(1);
  await t.throwsAsync(
    async () => {
      await decode(jwt);
    },
    { instanceOf: Error, message: /not a nats jwt/ },
  );
});

test("jwt - encodes/decodes v1", async (t) => {
  const akp = createAccount();
  const token = await encodeAccount("A", akp, {}, { algorithm: Algorithms.v1 });
  const ac = await decode(token);
  t.plan(9);
  t.is(version(ac), 1);
  t.not(version(ac), 2);
  t.false(isOperator(ac));
  t.true(isAccount(ac));
  t.false(isUser(ac));
  t.false(isGeneric(ac));
  t.false(isActivation(ac));
  t.is(ac.type, Types.Account);
  t.deepEqual(ac.nats, {});
});

test("jwt - rejects bad type", async (t) => {
  const jwt =
    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;

  const chunks = jwt.split(".");
  chunks[0] = Base64UrlCodec.encode(
    JSON.stringify({ typ: "Foo", alg: "ed25519-nkey" }),
  );

  t.plan(1);
  await t.throwsAsync(
    async () => {
      await decode(chunks.join("."));
    },
    { instanceOf: Error, message: /not a nats jwt/ },
  );
});

test("jwt - rejects bad signature", async (t) => {
  const akp = createAccount();
  const token = await encodeAccount("A", akp);
  const chunks = token.split(".");
  chunks[2] = chunks[2].split("").reverse().join("");
  t.plan(1);
  await t.throwsAsync(
    async () => {
      await decode(chunks.join("."));
    },
    {
      instanceOf: Error,
      message: /sig verification failed/,
    },
  );
});
