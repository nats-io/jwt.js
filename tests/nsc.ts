// Copyright 2021 The NATS Authors
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

import { dirname, join } from "https://deno.land/std/path/mod.ts";
import { ensureDir } from "https://deno.land/std@0.103.0/fs/mod.ts";
import { assert } from "https://deno.land/std/testing/asserts.ts";
import { nuid } from "https://raw.githubusercontent.com/nats-io/nats.deno/main/nats-base-client/nuid.ts";
import type { KeyPair } from "../src/mod.ts";
import { Account, decode, fromSeed, Types } from "../src/mod.ts";

const root = await Deno.makeTempDir();
const storeDir = join(root, "store");
const keysDir = join(root, "keystore");

Deno.env.set("NKEYS_PATH", keysDir);
await run("env", "--store", storeDir);

export interface Std {
  out: string;
  err: string;
}

export interface Nsc {
  addOperator(): Promise<[string, Std]>;
  getOperator(n: string): Promise<string>;
  getAccount(o: string, a: string): Promise<string>;
  getUser(o: string, a: string, u: string): Promise<string>;
  run(...args: string[]): Promise<Std>;
  store(token: string): Promise<void>;
  findKeyPair(pk: string): Promise<KeyPair>;
}

export const nsc: Nsc = {
  async addOperator(): Promise<[string, Std]> {
    const name = nuid.next();
    const std = await run("add", "operator", name);
    return [name, std];
  },
  getOperator(n: string): Promise<string> {
    return Deno.readTextFile(operatorPath(n));
  },
  getAccount(o: string, a: string): Promise<string> {
    return Deno.readTextFile(accountPath(o, a));
  },
  getUser(o: string, a: string, u: string): Promise<string> {
    return Deno.readTextFile(userPath(o, a, u));
  },
  async findKeyPair(pk: string): Promise<KeyPair> {
    const fp = join(keysDir, "keys", pk[0], pk.slice(1, 3), `${pk}.nk`);
    const seed = await Deno.readTextFile(fp);
    return fromSeed(new TextEncoder().encode(seed));
  },
  async store(token: string): Promise<void> {
    const claim = await decode(token);
    const std = await run("describe", "operator", "--field", "name");
    const o = JSON.parse(std.out);
    let path: string;
    const type = (claim.nats as Account).type;
    switch (type) {
      case Types.Account:
        path = accountPath(o, claim.name);
        break;
      case Types.User: {
        const m = await keysToNames();
        const name = m.get(claim.iss);
        if (!name) {
          throw new Error("unable to find account");
        }
        path = userPath(o, name, claim.name);
        break;
      }
      default:
        throw new Error(`unsupported store for ${claim.type}`);
    }
    await ensureDir(dirname(path));
    return Deno.writeTextFile(path, token);
  },
  run: run,
};

async function keysToNames(): Promise<Map<string, string>> {
  const std = await run("list", "keys", "-A");
  const fields = parseTable(std.out);
  const map = new Map<string, string>();
  let lastName: string;
  fields.forEach((a) => {
    let [name, key] = a;
    if (name) {
      lastName = name;
    }
    // table may have an empty value if it was listing a signing key
    if (name == "") {
      name = lastName;
    }
    map.set(key, name);
  });
  return map;
}

// this will work for most simple tables
export function parseTable(s: string): string[][] {
  // split the lines
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

function operatorPath(n: string): string {
  return join(storeDir, n, `${n}.jwt`);
}

function accountPath(o: string, a: string): string {
  return join(storeDir, o, "accounts", a, `${a}.jwt`);
}

function userPath(o: string, a: string, u: string): string {
  return join(storeDir, o, "accounts", a, "users", `${u}.jwt`);
}

async function run(...args: string[]): Promise<Std> {
  const cmd = [Deno.env.get("CI") ? "/home/runner/work/jwt.js/jwt.js/nsc" : "nsc"];
  cmd.push(...args);
  const nsc = Deno.run({
    cmd: cmd,
    stderr: "piped",
    stdout: "piped",
    stdin: "null",
    env: {
      NKEYS_PATH: keysDir,
    },
  });
  const { success } = await nsc.status();
  const out = new TextDecoder().decode(await nsc.output());
  const err = new TextDecoder().decode(await nsc.stderrOutput());
  assert(success);
  nsc.close();
  return Promise.resolve({ out, err });
}
