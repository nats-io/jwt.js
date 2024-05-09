// Copyright 2020-2024 The NATS Authors
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

import type {
  Account,
  Activation,
  ClaimsData,
  Generic,
  IssuerAccount,
  Limits,
  NatsLimits,
  Permission,
  Permissions,
  ResponsePermissions,
  User,
  UserLimits,
  UserPermissionsLimits,
} from "./types.ts";

import {
  Types
} from "./types.ts";

import { decode } from "./jwt.ts";

/**
 * Returns true if the ClaimsData is for an Operator
 * @param c
 */
export function isOperator(c: ClaimsData<unknown>): c is ClaimsData<Generic> {
  const gen = c.nats as Generic;
  const type = version(c) === 1 ? c.type : gen.type;
  return type === Types.Operator;
}

/**
 * Returns true if the ClaimsData is for an Account
 * @param c
 */
export function isAccount(c: ClaimsData<unknown>): c is ClaimsData<Generic> {
  const gen = c.nats as Generic;
  const type = version(c) === 1 ? c.type : gen.type;
  return type === Types.Account;
}

/**
 * Returns true if the ClaimsData is for a User
 * @param c
 */
export function isUser(c: ClaimsData<unknown>): c is ClaimsData<Generic> {
  const gen = c.nats as Generic;
  const type = version(c) === 1 ? c.type : gen.type;
  return type === Types.User;
}

/**
 * Returns true if the ClaimsData is for an Activation
 * @param c
 */
export function isActivation(c: ClaimsData<unknown>): c is ClaimsData<Generic> {
  const gen = c.nats as Generic;
  const type = version(c) === 1 ? c.type : gen.type;
  return type === Types.Activation;
}

/**
 * Returns true if the ClaimsData is generic
 * @param c
 */
export function isGeneric(c: ClaimsData<unknown>): c is ClaimsData<Generic> {
  return !isAccount(c) && !isUser(c) && !isActivation(c);
}

/**
 * Returns the version of the JWT
 * @param c
 */
export function version(c: ClaimsData<unknown>): number {
  const gen = c.nats as Generic;
  return gen.version ? gen.version : 1;
}

export function defaultNatsLimits(): Required<NatsLimits> {
  return { data: -1, payload: -1, subs: -1 };
}

export function defaultResponsePermissions(): Required<ResponsePermissions> {
  return { max: 0, ttl: 0 };
}

export function defaultPermission(): Required<Permission> {
  return { allow: [], deny: [] };
}

export function defaultPermissions(): Permissions {
  const perms = {
    pub: defaultPermission(),
    sub: defaultPermission(),
  } as Permissions;
  perms.resp = defaultResponsePermissions();
  return perms;
}

export function defaultUserLimits(): Required<UserLimits> {
  return { src: [], times: [], locale: "" };
}

export function defaultUserPermissionsLimits(
  d: Partial<UserPermissionsLimits> | Partial<Permissions> | Partial<Limits> =
    {} as Partial<UserPermissionsLimits>,
): UserPermissionsLimits {
  return extend(
    defaultNatsLimits(),
    defaultUserLimits(),
    defaultPermissions(),
    { bearer_token: false, allowed_connection_types: [] },
    d,
  ) as UserPermissionsLimits;
}

export function defaultUser(d: Partial<User> = {}): Partial<User> {
  return extend({ data: -1, payload: -1, subs: -1 }, d) as Partial<User>;
}

export function extend(a: unknown, ...b: unknown[]): unknown {
  for (let i = 0; i < b.length; i++) {
    const o = b[i];
    //@ts-ignore: raw
    Object.assign(a, o);
  }
  return a;
}

export function randomValues(array: Uint8Array) {
  for (let i = 0; i < array.length; i++) {
    array[i] = Math.floor(Math.random() * 255);
  }
}

export function randomID(): string {
  const buf = new Uint8Array(12);
  randomValues(buf);
  const a = Array.from(buf);
  return btoa(String.fromCharCode(...a));
}

export function issuer(claim: ClaimsData<unknown>): string {
  const ia = claim.nats as IssuerAccount;
  return ia.issuer_account ? ia.issuer_account : claim.iss;
}

export async function equivalent(
  a: string,
  b: string,
  debug = false,
): Promise<boolean> {
  // remove the iat - issued at, and the jti as these will be
  // different unless the same JWT
  const replacer = (k: string, v: unknown): unknown => {
    return (k === "iat" || k === "jti") ? undefined : v;
  };

  // if we are looking at an account claim, we need to expand
  // any tokens we have as we also must remove iat and jti
  const expandTokens = (c: ClaimsData<Account>) => {
    c.nats.imports = c.nats.imports ?? [];
    c.nats.imports.forEach((im) => {
      if (im.token) {
        const td = decode<Activation>(im.token);
        im.token = JSON.stringify(td, replacer, " ");
      }
    });
  };

  const ca = await decode(a);
  if (isAccount(ca)) {
    expandTokens(ca);
  }
  const cb = await decode(b);
  if (isAccount(cb)) {
    expandTokens(cb);
  }

  const as = JSON.stringify(ca, replacer, " ");
  const bs = JSON.stringify(cb, replacer, " ");
  if (debug) {
    console.log(as, "===", bs);
  }
  return as === bs;
}
