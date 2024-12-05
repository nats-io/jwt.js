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

import { parseArgs } from "jsr:@std/cli@0.224.3/parse-args";
import {
  basename,
  extname,
  join,
  resolve,
} from "https://deno.land/std@0.136.0/path/mod.ts";

const argv = parseArgs(
  Deno.args,
  {
    alias: {
      o: ["out"],
    },
    boolean: true,
    string: ["out"],
    default: {
      o: "lib",
    },
  },
);

// resolve the specified directories to fq
const dirs = (argv._ as string[]).map((n) => {
  return resolve(n);
});
// resolve the out dir
const out = resolve(argv.o);

// collect a list of all the files
const files: string[] = [];
for (const d of dirs) {
  for await (const fn of Deno.readDir(d)) {
    const ext = extname(fn.name);
    if (ext === ".ts" || ext === ".js") {
      files.push(join(d, fn.name));
    }
  }
}

dirs.flat();

if (argv.debug) {
  console.log(`src: ${dirs.join(" ")}`);
  console.log(`out: ${out}`);
  console.log(`files: ${files.join(",")}`);
  Deno.exit(0);
}

if (!dirs.length || argv.h || argv.help) {
  console.log(
    `deno run --allow-all cjs-fix-imports [--debug] [--out build/] dir/ dir2/`,
  );
  Deno.exit(1);
}

// create out if not exist
await Deno.lstat(out)
  .catch(async () => {
    await Deno.mkdir(out, { recursive: true });
  });

// process each file - remove extensions from requires/import
for (const fn of files) {
  const data = await Deno.readFile(fn);
  const txt = new TextDecoder().decode(data);

  let mod = txt.replace(/jsr:@nats-io\/nkeys/gim, "@nats-io/nkeys");
  mod = mod.replace(/jsr:@nats-io\/nuid/gim, "@nats-io/nuid");
  mod = mod.replace(/jsr:@nats-io\/nats-core/gim, "@nats-io/nats-core");
  if (!fn.endsWith("nkeys.ts") && !fn.endsWith("nuid.ts")) {
    mod = mod.replace(/from\s+"(\S+).[t|j]s"/gim, 'from "$1"');
  }

  const target = join(out, basename(fn));
  await Deno.writeFile(target, new TextEncoder().encode(mod));
  if (txt.length !== mod.length) {
    console.log(`${target}`);
  }
}
