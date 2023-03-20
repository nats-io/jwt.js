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
import { ensureDir } from "https://deno.land/std/fs/mod.ts";
import { assert } from "https://deno.land/std/testing/asserts.ts";
import { nuid } from "https://raw.githubusercontent.com/nats-io/nats.deno/main/nats-base-client/nuid.ts";
import type { KeyPair } from "../src/mod.ts";
import { Account, decode, fromSeed, Types } from "../src/mod.ts";
import RunOptions = Deno.RunOptions;

let root;

if (!Deno.env.has("XDG_CONFIG_HOME")) {
  root = await Deno.makeTempDir();
  const config = join(root, "config");
  Deno.env.set("XDG_CONFIG_HOME", config);
}
if (
  Deno.env.has("XDG_DATA_HOME") === false
) {
  root = root ?? await Deno.makeTempDir();
  const storeDir = join(root, "data");
  Deno.env.set("XDG_DATA_HOME", storeDir);
}

export function setNscData(p: string) {
  Deno.env.set("XDG_DATA_HOME", p);
}

export function setNscConfig(p: string) {
  Deno.env.set("XDG_CONFIG_HOME", p);
}

export function setNKeysDir(p: string) {
  Deno.env.set("NKEYS_PATH", p);
}

export function getDataHome(): string {
  const p = Deno.env.get("XDG_DATA_HOME") ?? "";
  return p;
}

export function getConfigHome(): string {
  return join(Deno.env.get("XDG_CONFIG_HOME") ?? "");
}

export function getKeysDir(): string {
  if (Deno.env.has("NKEYS_PATH")) {
    return Deno.env.get("NKEYS_PATH")!;
  }
  return join(getDataHome(), "nats", "nsc", "keys");
}

export function getStoresDir(): string {
  const stores = join(
    Deno.env.get("XDG_DATA_HOME") ?? "",
    "nats",
    "nsc",
    "stores",
  );
  return stores;
}

export interface Std {
  out: string;
  err: string;
}

export interface Nsc {
  env(): Promise<Std>;
  addOperator(): Promise<[string, Std]>;
  getOperator(n: string): Promise<string>;
  getAccount(o: string, a: string): Promise<string>;
  getUser(o: string, a: string, u: string): Promise<string>;
  run(...args: string[]): Promise<Std>;
  store(token: string): Promise<void>;
  findKeyPair(pk: string): Promise<KeyPair>;
}

export const nsc: Nsc = {
  async env(): Promise<Std> {
    return await run("env");
  },
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
    const fp = join(getKeysDir(), "keys", pk[0], pk.slice(1, 3), `${pk}.nk`);
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
  const p = join(getStoresDir(), n, `${n}.jwt`);
  return p;
}

function accountPath(o: string, a: string): string {
  const p = join(getStoresDir(), o, "accounts", a, `${a}.jwt`);
  return p;
}

function userPath(o: string, a: string, u: string): string {
  const p = join(getStoresDir(), o, "accounts", a, "users", `${u}.jwt`);
  return p;
}

async function run(...args: string[]): Promise<Std> {
  const cmd = [
    Deno.env.get("CI") ? "/home/runner/work/jwt.js/jwt.js/nsc" : "nsc",
  ];
  cmd.push(...args);
  const opts: RunOptions = {
    cmd: cmd,
    stderr: "piped",
    stdout: "piped",
    stdin: "null",
    env: {
      XDG_DATA_HOME: getDataHome(),
      XDG_CONFIG_HOME: getConfigHome(),
    },
  };
  const nsc = Deno.run(opts);
  const { success } = await nsc.status();
  const out = new TextDecoder().decode(await nsc.output());
  const err = new TextDecoder().decode(await nsc.stderrOutput());
  assert(success);
  nsc.close();
  return Promise.resolve({ out, err });
}
