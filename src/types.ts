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

export enum Types {
  Operator = "operator",
  Account = "account",
  User = "user",
  Activation = "activation",
  AuthorizationResponse = "authorization_response",
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
  disallow_bearer: boolean;
}

export interface JetStreamLimits {
  "mem_storage": number;
  "disk_storage": number;
  streams: number;
  consumer: number;
  "mem_max_stream_bytes": number;
  "disk_max_stream_bytes": number;
  "max_bytes_required": boolean;
  "max_ack_pending": number;
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

export type User = UserPermissionsLimits & IssuerAccount & GenericFields;

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

export type ActivationContents = {
  subject: string;
  kind?: "stream" | "service";
};
export type Activation = VersionType & IssuerAccount & ActivationContents;
export interface VersionType {
  type?: Types | string;
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

export interface Operator extends GenericFields {
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
  "disallow_bearer"?: boolean;
}

export interface ScopedUser extends GenericFields {
  "issuer_account"?: string;
  "bearer_token"?: boolean;
  "allowed_connection_types"?: ConnectionType[];
}

export interface IssuerAccount {
  "issuer_account"?: string;
}

export interface AuthorizationResponse extends GenericFields, IssuerAccount {
  error?: string;
  jwt?: string;
}

export type AuthorizationRequest = {
  readonly server_id: ServerId;
  readonly user_nkey: string;
  readonly client_info: ClientInfo;
  readonly connect_opts: ConnectOpts;
  readonly client_tls?: ClientTls;
  readonly request_nonce?: string;
  readonly tags?: ReadonlyArray<string>;
  readonly type?: string;
  readonly version?: number;
};

export type ServerId = {
  readonly name: string;
  readonly host: string;
  readonly id: string;
  readonly version?: string;
  readonly cluster?: string;
  readonly tags?: ReadonlyArray<string>;
  readonly xkey?: string;
};

export type ClientInfo = {
  readonly host?: string;
  readonly id?: number;
  readonly user?: string;
  readonly name?: string;
  readonly tags?: ReadonlyArray<string>;
  readonly name_tag?: string;
  readonly kind?: string;
  readonly type?: string;
  readonly mqtt_id?: string;
  readonly nonce?: string;
};

export type ConnectOpts = {
  readonly jwt?: string;
  readonly nkey?: string;
  readonly sig?: string;
  readonly auth_token?: string;
  readonly user?: string;
  readonly pass?: string;
  readonly name?: string;
  readonly lang?: string;
  readonly version?: string;
  readonly protocol: number;
};

export type ClientTls = {
  readonly version?: string;
  readonly cipher?: string;
  readonly certs?: ReadonlyArray<string>;
  readonly verified_chains?: ReadonlyArray<ReadonlyArray<string>>;
};
