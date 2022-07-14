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
  Account,
  Activation,
  ClaimsData,
  Generic,
  Operator,
  SigningKey,
  Types,
  User,
  UserPermissionsLimits,
  ValidDates,
} from "./types.ts";
import {
  defaultUser,
  defaultUserPermissionsLimits,
  extend,
  randomID,
} from "./util.ts";
import { checkKey, Key } from "./keys.ts";
import { KeyPair } from "./nkeys.ts";
import { Base64Codec, Base64UrlCodec } from "./base64.ts";

/**
 * Enum capturing the JWT algorithm
 */
export enum Algorithms {
  v1 = "ed25519",
  v2 = "ed25519-nkey",
}

export interface UserEncodingOptions extends EncodingOptions {
  scopedUser?: boolean;
}

export interface EncodingOptions extends ValidDates {
  algorithm: Algorithms;
  signer?: Key;
}

function initClaim<T>(opts: Partial<EncodingOptions>): ClaimsData<T> {
  const { exp, nbf } = opts;
  return extend({}, { exp, nbf }) as ClaimsData<T>;
}

function initAlgorithm(opts: Partial<EncodingOptions> = {}): EncodingOptions {
  if (!opts.algorithm) {
    opts.algorithm = Algorithms.v2;
  }
  return opts as EncodingOptions;
}

/**
 * Generates an operator JWT
 * @param name - the operator name
 * @param okp - a key representing the operator
 * @param operator - operator options
 * @param opts - encoding options
 */
export async function encodeOperator(
  name: string,
  okp: Key,
  operator: Partial<Operator> = {},
  opts: Partial<EncodingOptions> = {},
): Promise<string> {
  okp = checkKey(okp, "O", !opts.signer);
  let signer = okp;
  if (opts.signer) {
    signer = checkKey(opts.signer, ["O"], true);
  }
  const claim = initClaim<Operator>(opts);
  claim.name = name;
  claim.sub = okp.getPublicKey();
  claim.nats = operator;
  const o = initAlgorithm(opts);
  setVersionType(o.algorithm, Types.Operator, claim);
  return await encode(o.algorithm, claim, signer);
}

/**
 * Generates an account JWT with the specified name having the identity of the
 * providedd Key.
 * @param name
 * @param akp
 * @param account
 * @param opts
 */
export async function encodeAccount(
  name: string,
  akp: Key,
  account: Partial<Account> = {},
  opts: Partial<EncodingOptions> = {},
): Promise<string> {
  akp = checkKey(akp, "A", !opts.signer);
  let signer = akp;
  if (opts.signer) {
    signer = checkKey(opts.signer, ["O", "A"], true);
  }
  const claim = initClaim<Account>(opts);
  claim.name = name;
  claim.sub = akp.getPublicKey();
  claim.nats = account;
  const o = initAlgorithm(opts);
  setVersionType(o.algorithm, Types.Account, claim);
  return await encode(o.algorithm, claim, signer);
}

export async function encodeUser(
  name: string,
  ukp: Key,
  issuer: Key,
  user: Partial<User> = {},
  opts: Partial<UserEncodingOptions> = {},
): Promise<string> {
  issuer = checkKey(issuer, "A", !opts.signer);
  let signer = issuer;
  if (opts.signer) {
    signer = checkKey(opts.signer, "A", true);
  }
  ukp = checkKey(ukp, "U");
  const claim = initClaim<User>(opts);
  claim.name = name;
  claim.sub = ukp.getPublicKey();
  claim.nats = opts.scopedUser ? user : defaultUser(user);
  if (opts.signer) {
    claim.nats.issuer_account = issuer.getPublicKey();
  }
  claim.aud = "NATS";
  const o = initAlgorithm(opts);
  setVersionType(o.algorithm, Types.User, claim);
  return await encode(o.algorithm, claim, signer);
}

export function encodeActivation(
  name: string,
  subject: Key,
  issuer: Key,
  kind: "service" | "stream",
  data: Partial<Activation> = {},
  opts: Partial<EncodingOptions> = {},
): Promise<string> {
  subject = checkKey(subject, "", false);
  issuer = checkKey(issuer, "", !opts.signer);
  let signer = issuer;
  if (opts.signer) {
    signer = checkKey(opts.signer, "", true);
  }
  const claim = initClaim<Generic>(opts);
  claim.name = name;
  claim.sub = subject.getPublicKey();
  claim.nats = data;
  if (opts.signer) {
    claim.nats.issuer_account = issuer.getPublicKey();
  }
  const o = initAlgorithm(opts);
  const key = o.algorithm === Algorithms.v2 ? "kind" : "type";
  claim.nats[key] = kind;
  setVersionType(o.algorithm, Types.Activation, claim);
  return encode(o.algorithm, claim, signer);
}

export async function encodeGeneric(
  name: string,
  akp: Key,
  kind: string,
  data: Partial<Generic> = {},
  opts: Partial<EncodingOptions> = {},
): Promise<string> {
  akp = checkKey(akp, "");
  const claim = initClaim<Generic>(opts);
  claim.name = name;
  claim.nats = data;
  claim.sub = akp.getPublicKey();
  const o = initAlgorithm(opts);
  setVersionType(o.algorithm, kind, claim);
  return await encode(o.algorithm, claim, akp);
}

function setVersionType(
  version: Algorithms,
  type: Types | string,
  claim: ClaimsData<Generic>,
) {
  claim.aud = "NATS";
  if (version === Algorithms.v2) {
    claim.nats.type = type;
  } else {
    claim.type = type;
  }
}

export function decode<T = unknown>(jwt: string): ClaimsData<T> {
  const chunks = jwt.split(".");
  if (chunks.length !== 3) {
    throw new Error(`invalid jwt - ${chunks.length} chunks: ${jwt}`);
  }

  const h = JSON.parse(Base64UrlCodec.decode(chunks[0]) as string);
  if (h.typ !== "jwt" && h.typ !== "JWT") {
    throw new Error(`not a nats jwt - typ ${h.type}`);
  }
  if (h.alg !== Algorithms.v1 && h.alg !== Algorithms.v2) {
    throw new Error(`not a nats jwt - alg ${h.alg}`);
  }

  const b = JSON.parse(
    Base64UrlCodec.decode(chunks[1]) as string,
  ) as ClaimsData<unknown>;
  const ipk = checkKey(b.iss);

  const sig = Base64UrlCodec.decode(chunks[2], true) as Uint8Array;
  const te = new TextEncoder();

  const payload = h.alg === Algorithms.v2
    ? `${chunks[0]}.${chunks[1]}`
    : chunks[1];

  if (!ipk.verify(te.encode(payload), sig)) {
    throw new Error("sig verification failed");
  }
  return b as ClaimsData<T>;
}

async function encode(
  version: Algorithms,
  claim: ClaimsData<unknown>,
  kp: KeyPair,
): Promise<string> {
  claim.iss = kp.getPublicKey();
  claim.iat = Math.floor(Date.now() / 1000);

  const gc = claim as ClaimsData<Generic>;
  if (version === Algorithms.v2) {
    gc.nats.version = 2;
  }

  const te = new TextEncoder();
  const data = te.encode(JSON.stringify(claim));
  // this should be a crypto hash  - on browser:
  if (globalThis.crypto && globalThis.crypto.subtle) {
    //@ts-ignore: this is a global object on a browser
    const hash = await globalThis.crypto.subtle.digest("SHA-512", data);
    claim.jti = Base64Codec.encode(new Uint8Array(hash));
  } else {
    claim.jti = randomID();
  }

  const header = {
    typ: "JWT",
    alg: version,
  };
  const hstr = Base64UrlCodec.encode(JSON.stringify(header));
  const bstr = Base64UrlCodec.encode(JSON.stringify(claim));
  const payload = version === Algorithms.v2 ? `${hstr}.${bstr}` : bstr;
  const sig = Base64UrlCodec.encode(kp.sign(te.encode(payload)));

  return `${hstr}.${bstr}.${sig}`;
}

export function newScopedSigner(
  signer: Key,
  role: string,
  limits: Partial<UserPermissionsLimits>,
): SigningKey {
  signer = checkKey(signer, "A", false);
  limits = defaultUserPermissionsLimits(limits);
  const s = {} as SigningKey;
  s.key = signer.getPublicKey();
  s.role = role;
  s.kind = "user_scope";
  s.template = limits;
  return s;
}

export function fmtCreds(token: string, kp: KeyPair): Uint8Array {
  const s = new TextDecoder().decode(kp.getSeed());
  const creds = `-----BEGIN NATS USER JWT-----
${token}
------END NATS USER JWT------

************************* IMPORTANT *************************
NKEY Seed printed below can be used sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
${s}
------END USER NKEY SEED------
`;
  return new TextEncoder().encode(creds);
}

export async function parseCreds(
  creds: Uint8Array,
): Promise<{ key: string; jwt: string; uc: ClaimsData<User>; aid: string }> {
  const TD = new TextDecoder();
  const CREDS =
    /\s*(?:(?:[-]{3,}[^\n]*[-]{3,}\n)(.+)(?:\n\s*[-]{3,}[^\n]*[-]{3,}\n))/ig;
  const s = TD.decode(creds);
  // get the JWT
  let m = CREDS.exec(s);
  if (!m) {
    return Promise.reject(new Error("bad credentials"));
  }
  const jwt = m[1].trim();
  const uc = await decode<User>(jwt);
  const aid = uc.nats.issuer_account ? uc.nats.issuer_account : uc.iss;

  // next match is the key
  m = CREDS.exec(s);
  if (!m) {
    return Promise.reject(new Error("bad credentials"));
  }
  const key = m[1].trim();
  return Promise.resolve({ key, jwt, uc, aid });
}
