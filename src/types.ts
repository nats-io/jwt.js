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

export enum Types {
  Operator = "operator",
  Account = "account",
  User = "user",
  Activation = "activation",
}

export interface NatsLimits {
  data: number;
  payload: number;
  subs: number;
}

export interface AccountLimits {
  imports: number;
  exports: number;
  wildcards: boolean;
  conn: number;
  leaf: number;
}

export interface JetStreamLimits {
  "mem_storage": number;
  "disk_storage": number;
  streams: number;
  consumer: number;
  "max_bytes_required": boolean;
}

export type JetStreamTieredLimits = {
  tiered_limits?: {
    R1?: Partial<JetStreamLimits>;
    R3?: Partial<JetStreamLimits>;
  };
};

export type OperatorLimits =
  & Partial<NatsLimits>
  & Partial<AccountLimits>
  & Partial<JetStreamLimits>
  & Partial<JetStreamTieredLimits>;

export interface ResponsePermissions {
  max: number;
  ttl: number;
}

export interface Permission {
  allow: string[];
  deny: string[];
}

export interface Permissions {
  pub: Permission;
  sub: Permission;
  resp: ResponsePermissions;
}

export interface TimeRange {
  start?: string;
  end?: string;
}

export interface UserLimits {
  src?: string[];
  times?: TimeRange[];
  locale?: string;
}

export type Limits = UserLimits & NatsLimits;

export type ConnectionType =
  | "STANDARD"
  | "WEBSOCKET"
  | "LEAFNODE"
  | "LEAFNODE_WS"
  | "MQTT"
  | "MQTT_WS";

export interface UserPermissionsLimits extends Permissions, Limits {
  "bearer_token": boolean;
  "allowed_connection_types": ConnectionType[];
}

export type User = UserPermissionsLimits & IssuerAccount;

export interface ValidDates {
  exp?: number;
  nbf?: number;
}

export interface ClaimsData<T> extends ValidDates {
  aud: string;
  jti: string;
  iat: number;
  iss: string;
  name: string;
  sub: string;
  nats: Partial<T>;

  // only on v1
  type?: Types | string;
}

export type Generic = Record<string, unknown> & VersionType & IssuerAccount;

export interface VersionType {
  type: Types | string;
  version: number;
}

export interface base {
  name: string;
  subject: string;
  type: "stream" | "service";
}

export type Imports = Import[];
export interface Import extends base {
  account: string;
  token?: string;
  to?: string;
  "local_subject"?: string;
  share?: boolean;
}

export type Exports = Export[];
export interface Export extends base, Info {
  "token_req"?: boolean;
  revocations?: RevocationList;
  "response_type"?: "Singleton" | "Stream" | "Chunked";
  "response_threshold"?: number;
  "service_latency"?: ServiceLatency;
  "account_token_position"?: number;
}

export interface ServiceLatency {
  sampling: string;
  results: string;
}

export interface Info {
  description?: string;
  "info_url"?: string;
}

export type RevocationList = Record<string, number>;

export interface GenericFields extends VersionType {
  tags?: string[];
}

export type SigningKeys = (SigningKey | string)[];

export interface SigningKey {
  kind: "user_scope";
  key: string;
  role: string;
  template: Partial<UserPermissionsLimits>;
}

export interface Operator {
  "signing_keys"?: SigningKeys;
  "account_server_url"?: string;
  "operator_service_urls"?: string[];
  "system_account"?: string;
}

export interface Account extends Info, GenericFields {
  imports?: Imports;
  exports?: Exports;
  limits?: OperatorLimits;
  "signing_keys"?: SigningKeys;
  revocations?: RevocationList;
  "default_permissions"?: Partial<Permissions>;
}

export interface ScopedUser extends GenericFields {
  "issuer_account"?: string;
  "bearer_token"?: boolean;
  "allowed_connection_types"?: ConnectionType[];
}

export interface IssuerAccount {
  "issuer_account"?: string;
}
