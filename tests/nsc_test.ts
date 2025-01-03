import {
  getConfigHome,
  getKeysDir,
  getStoresDir,
  nsc,
  parseTable,
  setNKeysDir,
  setNscConfig,
  setNscData,
} from "./nsc.ts";
import { assert, assertEquals, assertFalse } from "@std/assert";
import { join } from "@std/path";

function homeDir(p?: string) {
  if (p?.includes("~/")) {
    p = p.replace("~", Deno.env.get("HOME") ?? "");
  }
  return p;
}

Deno.test("nsc - env", async () => {
  const std = await nsc.env();
  const table = parseTable(std.err);
  const nscHome = table.find((v) => {
    return v[0] === "$NSC_HOME (deprecated)";
  })?.[2];
  if (nscHome) {
    assertEquals(homeDir(nscHome), join(getConfigHome(), "nats", "nsc"));
  }

  const nkeys = table.find((v) => {
    return v[0] === "$NKEYS_PATH (deprecated)";
  });
  const nkeysPath = nkeys?.[2];
  assertEquals(homeDir(nkeysPath), getKeysDir());
  const nkeysPathSet = nkeys?.[1] === "Yes" || false;
  assertFalse(nkeysPathSet);

  const storeDir = table.find((v) => {
    return v[0] === "Default Stores Dir";
  })?.[2];
  assertEquals(homeDir(storeDir), getStoresDir());
});

Deno.test("nsc - set env nkeys_path", async () => {
  const dir = await Deno.makeTempDir({ prefix: "my_test_" });
  setNscData(join(dir, "data"));
  setNscConfig(join(dir, "config"));
  const nkeysDir = join(dir, "this_are_my_keys");
  setNKeysDir(nkeysDir);

  const std = await nsc.env();
  const table = parseTable(std.err);
  const nscHome = table.find((v) => {
    return v[0] === "$NSC_HOME (deprecated)";
  })?.[2];
  assertEquals(homeDir(nscHome), join(getConfigHome(), "nats", "nsc"));
  assert(nscHome?.includes("my_test_"));

  const nkeys = table.find((v) => {
    return v[0] === "$NKEYS_PATH (deprecated)";
  });
  const nkeysPath = nkeys?.[2];
  assertEquals(homeDir(nkeysPath), nkeysDir);
  assert(nkeysPath?.includes("my_test_"));

  const nkeysPathSet = nkeys?.[1] === "Yes" || false;
  assert(nkeysPathSet);

  const storeDir = table.find((v) => {
    return v[0] === "Default Stores Dir";
  })?.[2];
  assertEquals(homeDir(storeDir), getStoresDir());
  assert(storeDir?.includes("my_test_"));
});

Deno.test("nsc - set nkeys dir", async () => {
  const dir = await Deno.makeTempDir({ prefix: "my_test_" });
  setNscData(join(dir, "data"));
  setNscConfig(join(dir, "config"));

  const std = await nsc.env();

  const table = parseTable(std.err);
  const nscHome = table.find((v) => {
    return v[0] === "$NSC_HOME (deprecated)";
  })?.[2];
  assertEquals(nscHome, join(getConfigHome(), "nats", "nsc"));
  assert(nscHome?.includes("my_test_"));

  const nkeys = table.find((v) => {
    return v[0] === "$NKEYS_PATH (deprecated)";
  });
  const nkeysPath = nkeys?.[2];
  assertEquals(nkeysPath, getKeysDir());
  assert(nkeysPath?.includes("my_test_"));

  const nkeysPathSet = nkeys?.[1] === "Yes" || false;
  assert(nkeysPathSet);

  const storeDir = table.find((v) => {
    return v[0] === "Default Stores Dir";
  })?.[2];
  assertEquals(storeDir, getStoresDir());
  assert(storeDir?.includes("my_test_"));
});
