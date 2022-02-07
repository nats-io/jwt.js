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

import {
  assert,
  assertEquals,
  assertThrowsAsync,
  fail,
} from "https://deno.land/std@0.103.0/testing/asserts.ts";
import { nsc, parseTable } from "./nsc.ts";
import {
  Account,
  Algorithms,
  Base64UrlCodec,
  ClaimsData,
  createAccount,
  createOperator,
  createUser,
  decode,
  defaultUserPermissionsLimits,
  encodeAccount,
  encodeActivation,
  encodeGeneric,
  encodeOperator,
  encodeUser,
  isAccount,
  isActivation,
  isGeneric,
  isUser,
  newScopedSigner,
  Operator,
  Permissions,
  Types,
  User,
  version,
} from "../src/mod.ts";

Deno.test("parse table", () => {
  const t =
    `+---------------------------------------------------------------------------------------------------------------+
|                                                     Keys                                                      |
+-----------------------------+----------------------------------------------------------+-------------+--------+
| Entity                      | Key                                                      | Signing Key | Stored |
+-----------------------------+----------------------------------------------------------+-------------+--------+
| name_U80HBXY1E636R3QZ6KK1AQ | ODWPVMRX675TNBUERYNNFKT55BCUJ3TMNZMWVCAO3WZQGGI7HU4EY4ED |             |        |
|  A                          | ACFACYHVLD2I5R5E5R4U7UGOURWAUIWY4GGBN4NKFQXBUCDMADN5HJOE |             |        |
+-----------------------------+----------------------------------------------------------+-------------+--------+
`;
  const v = parseTable(t);
  assertEquals(v.length, 3);
  assertEquals(v[0][0], "Entity");
  assertEquals(v[0][1], "Key");
  assertEquals(v[0][2], "Signing Key");
  assertEquals(v[0][3], "Stored");
  assertEquals(v[1][0], "name_U80HBXY1E636R3QZ6KK1AQ");
  assertEquals(
    v[1][1],
    "ODWPVMRX675TNBUERYNNFKT55BCUJ3TMNZMWVCAO3WZQGGI7HU4EY4ED",
  );
  assertEquals(v[1][2], "");
  assertEquals(v[1][3], "");
  assertEquals(v[2][0], "A");
  assertEquals(
    v[2][1],
    "ACFACYHVLD2I5R5E5R4U7UGOURWAUIWY4GGBN4NKFQXBUCDMADN5HJOE",
  );
  assertEquals(v[2][2], "");
  assertEquals(v[2][3], "");
});

Deno.test("jwt - rejects bad chunks", async () => {
  const jwt = `eyJhbGciOiJIUzI1NiIsInR`;
  await assertThrowsAsync(
    async () => {
      await decode(jwt);
    },
    Error,
    "invalid jwt",
  );
});

Deno.test("jwt - rejects bad algorithm", async () => {
  const jwt =
    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;
  await assertThrowsAsync(
    async () => {
      await decode(jwt);
    },
    Error,
    "not a nats jwt",
  );
});

Deno.test("jwt - encodes/decodes v1", async () => {
  const akp = createAccount();
  const token = await encodeAccount("A", akp, {}, { algorithm: Algorithms.v1 });
  const ac = await decode<Account>(token);
  assertEquals(ac.type, Types.Account);
  assertEquals(ac.nats, {});
});

Deno.test("jwt - rejects bad type", async () => {
  const jwt =
    `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`;

  const chunks = jwt.split(".");
  chunks[0] = Base64UrlCodec.encode(
    JSON.stringify({ typ: "Foo", alg: "ed25519-nkey" }),
  );

  await assertThrowsAsync(
    async () => {
      await decode(chunks.join("."));
    },
    Error,
    "not a nats jwt",
  );
});

Deno.test("jwt - rejects bad signature", async () => {
  const akp = createAccount();
  const token = await encodeAccount("A", akp);
  const chunks = token.split(".");
  chunks[2] = chunks[2].split("").reverse().join("");
  await assertThrowsAsync(
    async () => {
      await decode<Account>(chunks.join("."));
    },
    Error,
    "sig verification failed",
  );
});

Deno.test("jwt - read account", async () => {
  const [o] = await nsc.addOperator();
  let std = await nsc.run("describe", "operator", "--field", "sub");
  const opk = JSON.parse(std.out);
  await nsc.run("add", "account", "A");
  const ac = await decode<Account>(await nsc.getAccount(o, "A"));

  std = await nsc.run("describe", "account", "A", "--json");
  const sa = JSON.parse(std.out);

  assertEquals(ac.name, sa.name);
  assertEquals(ac.sub, sa.sub);
  assertEquals(ac.iss, opk);
  assertEquals(ac.iss, sa.iss);
});

Deno.test("jwt - write account", async () => {
  await nsc.addOperator();
  let std = await nsc.run("describe", "operator", "--field", "sub");
  const opk = JSON.parse(std.out);

  const okp = await nsc.findKeyPair(opk);
  const akp = createAccount();
  const token = await encodeAccount("A", akp, {}, { signer: okp });
  const ac = await decode<Account>(token);
  await nsc.store(token);

  std = await nsc.run("describe", "account", "A", "--json");
  const sa = JSON.parse(std.out);

  assertEquals(sa.name, ac.name);
  assertEquals(sa.sub, ac.sub);
  assertEquals(ac.iss, opk);
  assertEquals(sa.iss, ac.iss);
});

Deno.test("jwt - account signingkeys string", async () => {
  const akp = createAccount();
  const skp = createAccount();
  const jwt = await encodeAccount("A", akp, {
    signing_keys: [skp.getPublicKey()],
  });
  const ac = await decode<Account>(jwt);
  assert(ac.nats.signing_keys);
  assertEquals(ac.nats.signing_keys.length, 1);
  assertEquals(ac.nats.signing_keys[0], skp.getPublicKey());
});

Deno.test("jwt - account signingkeys scoped", async () => {
  const akp = createAccount();
  const skp = createAccount();
  const perm = defaultUserPermissionsLimits({
    sub: {
      allow: ["foo"],
    },
  } as Partial<Permissions>);
  const ss = newScopedSigner(skp, "anyrole", perm);
  const jwt = await encodeAccount("A", akp, {
    signing_keys: [ss],
  });
  const ac = await decode<Account>(jwt);
  assert(ac.nats.signing_keys);
  assertEquals(ac.nats.signing_keys.length, 1);
  assertEquals(ac.nats.signing_keys[0], ss);
});

Deno.test("jwt - check key", async () => {
  const akp = createAccount();
  await encodeAccount("A", akp);
  await encodeAccount("A", akp.getSeed());
  await encodeAccount("A", new TextDecoder().decode(akp.getSeed()));
});

Deno.test("jwt - account signer can be operator or account", async () => {
  const okp = createOperator();
  const akp = createAccount();
  const ukp = createUser();
  const id = createAccount();
  await encodeAccount("A", id, {} as Account, { signer: okp });
  await encodeAccount("A", id, {} as Account, { signer: akp });
  await assertThrowsAsync(
    async () => {
      await encodeAccount("A", id, {} as Account, { signer: ukp });
    },
    Error,
    "unexpected type U - wanted O,A",
  );
});

Deno.test("jwt - account id must be account", async () => {
  const okp = createOperator();
  const akp = createAccount();
  const ukp = createUser();
  await encodeAccount("A", akp, {} as Account, { signer: okp });
  await assertThrowsAsync(
    async () => {
      await encodeAccount("A", okp, {} as Account, { signer: okp });
    },
    Error,
    "unexpected type O - wanted A",
  );
  await assertThrowsAsync(
    async () => {
      await encodeAccount("A", ukp, {} as Account, { signer: okp });
    },
    Error,
    "unexpected type U - wanted A",
  );
});

Deno.test("jwt - user id must be user", async () => {
  const okp = createOperator();
  const akp = createAccount();
  const ukp = createUser();
  await encodeUser("A", ukp, akp);
  await assertThrowsAsync(
    async () => {
      await encodeUser("A", akp, akp);
    },
    Error,
    "unexpected type A - wanted U",
  );
  await assertThrowsAsync(
    async () => {
      await encodeUser("A", okp, akp);
    },
    Error,
    "unexpected type O - wanted U",
  );
});

Deno.test("jwt - user issuer must be account", async () => {
  const okp = createOperator();
  const akp = createAccount();
  const ukp = createUser();
  await encodeUser("A", ukp, akp);
  await assertThrowsAsync(
    async () => {
      await encodeUser("A", ukp, ukp);
    },
    Error,
    "unexpected type U - wanted A",
  );
  await assertThrowsAsync(
    async () => {
      await encodeUser("A", ukp, okp);
    },
    Error,
    "unexpected type O - wanted A",
  );
});

Deno.test("jwt - user issuer_account must be account", async () => {
  const okp = createOperator();
  const akp = createAccount();
  const ukp = createUser();
  await encodeUser("A", ukp, akp, {}, { signer: akp });
  await assertThrowsAsync(
    async () => {
      await encodeUser("A", ukp, akp, {}, { signer: ukp });
    },
    Error,
    "unexpected type U - wanted A",
  );
  await assertThrowsAsync(
    async () => {
      await encodeUser("A", ukp, akp, {}, { signer: okp });
    },
    Error,
    "unexpected type O - wanted A",
  );
});

Deno.test("jwt - ids can be public keys", async () => {
  const okp = createOperator();
  const akp = createAccount();
  const ukp = createUser();
  await encodeUser("U", ukp.getPublicKey(), akp);
  await encodeAccount("A", akp.getPublicKey(), {}, { signer: okp });
});

Deno.test("jwt - is account", async () => {
  const akp = createAccount();
  const ukp = createUser();
  assertEquals(isAccount(await decode(await encodeAccount("A", akp))), true);
  assertEquals(
    isAccount(await decode(await encodeUser("U", ukp.getPublicKey(), akp))),
    false,
  );
  assertEquals(
    isAccount(await decode(await encodeActivation("T", akp, akp))),
    false,
  );
  assertEquals(
    isAccount(await decode(await encodeGeneric("G", akp, "kind"))),
    false,
  );
});

Deno.test("jwt - is user", async () => {
  const akp = createAccount();
  const ukp = createUser();
  assertEquals(isUser(await decode(await encodeUser("U", ukp, akp))), true);
  assertEquals(
    isUser(await decode(await encodeAccount("A", akp))),
    false,
  );
  assertEquals(
    isUser(await decode(await encodeActivation("T", akp, akp))),
    false,
  );
  assertEquals(
    isUser(await decode(await encodeGeneric("G", akp, "kind"))),
    false,
  );
});

Deno.test("jwt - is activation", async () => {
  const akp = createAccount();
  const ukp = createUser();
  assertEquals(
    isActivation(await decode(await encodeActivation("T", akp, akp))),
    true,
  );
  assertEquals(
    isActivation(await decode(await encodeAccount("A", akp))),
    false,
  );
  assertEquals(
    isActivation(await decode(await encodeUser("U", ukp, akp))),
    false,
  );
  assertEquals(
    isActivation(await decode(await encodeGeneric("G", akp, "kind"))),
    false,
  );
});

Deno.test("jwt - is generic", async () => {
  const akp = createAccount();
  const ukp = createUser();
  assertEquals(
    isGeneric(await decode(await encodeGeneric("G", akp, "kind"))),
    true,
  );
  assertEquals(
    isGeneric(await decode(await encodeAccount("A", akp))),
    false,
  );
  assertEquals(
    isGeneric(await decode(await encodeUser("U", ukp, akp))),
    false,
  );
  assertEquals(
    isGeneric(await decode(await encodeActivation("", akp, akp))),
    false,
  );
});

Deno.test("jwt - version", async () => {
  const akp = createAccount();
  const ukp = createUser();

  type test = [string, number];
  const tests: test[] = [
    [await encodeAccount("A", akp, {}, { algorithm: Algorithms.v1 }), 1],
    [await encodeAccount("A", akp), 2],
    [await encodeUser("U", ukp, akp, {}, { algorithm: Algorithms.v1 }), 1],
    [await encodeUser("U", ukp, akp), 2],
    [
      await encodeGeneric("G", akp, "kind", {}, { algorithm: Algorithms.v1 }),
      1,
    ],
    [await encodeGeneric("G", akp, "kind"), 2],
    [
      await encodeActivation("T", akp, akp, {}, { algorithm: Algorithms.v1 }),
      1,
    ],
    [await encodeActivation("T", akp, akp, {}), 2],
  ];

  const proms: Promise<ClaimsData<unknown>>[] = [];
  tests.map((v) => {
    proms.push(decode(v[0]));
  });

  const cds = await Promise.allSettled(proms);
  cds.forEach((v, idx) => {
    if (v.status === "rejected") {
      fail(`${idx}: ${v.reason}`);
    } else {
      assertEquals(version(v.value), tests[idx][1]);
    }
  });
});

Deno.test("jwt - verify user issuer account", async () => {
  const akp = createAccount();
  const issuer = createAccount();

  const uc = await decode<User>(
    await encodeUser("U", createUser(), akp, {}, { signer: issuer }),
  );
  assertEquals(uc.iss, issuer.getPublicKey());
  assertEquals(uc.nats.issuer_account!, akp.getPublicKey());
});

Deno.test("jwt - verify activation issuer account", async () => {
  const akp = createAccount();
  const issuer = createAccount();

  const uc = await decode<User>(
    await encodeActivation("", createAccount(), akp, {}, { signer: issuer }),
  );
  assertEquals(uc.iss, issuer.getPublicKey());
  assertEquals(uc.nats.issuer_account!, akp.getPublicKey());
});

Deno.test("jwt - operator", async () => {
  const okp = createOperator();
  const oc = await decode<Operator>(
    await encodeOperator("O", okp, {}),
  );
  assertEquals(oc.name, "O");
});

Deno.test("jwt - scoped user", async () => {
  const akp = createAccount();
  const ukp = createUser();
  const tok = await encodeUser("U", ukp, akp, {}, { scopedUser: true });
  const uc = await decode<User>(tok);
  assertEquals(uc.nats.data, undefined);
  assertEquals(uc.nats.payload, undefined);
  assertEquals(uc.nats.subs, undefined);
});
