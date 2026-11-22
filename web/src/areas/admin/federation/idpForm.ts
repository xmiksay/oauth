// Form state of an identity provider and the request bodies built from it.
import type {
  IdentityProvider,
  IdentityProviderInput,
  IdentityProviderPatch,
  IdpClientAuth,
  IdpKind,
  IdpPolicy,
} from "@/api/types";

export const POLICIES: IdpPolicy[] = ["link_only", "jit", "deny"];

export const POLICY_LABELS: Record<IdpPolicy, string> = {
  jit: "Create accounts",
  link_only: "Link existing accounts",
  deny: "Linked identities only",
};

export const POLICY_HELP: Record<IdpPolicy, string> = {
  jit: "Create an account on first sign-in (needs a verified email; never links to an existing account)",
  link_only:
    "Unknown identities must sign in with an existing account once to link it",
  deny: "Only identities already linked may sign in",
};

export const CLIENT_AUTH_LABELS: Record<IdpClientAuth, string> = {
  post: "In the request body (client_secret_post)",
  basic: "HTTP Basic (client_secret_basic)",
};

const DEFAULT_SCOPES = ["openid", "email", "profile"];

/** What a preset fills in (all of it stays editable; the server applies the same defaults). */
export interface Preset {
  label: string;
  /** Suggested display name. */
  name: string;
  issuer: string;
  scopes: string[];
}

export const PRESETS: Record<IdpKind, Preset> = {
  oidc: {
    label: "OpenID Connect",
    name: "",
    issuer: "",
    scopes: DEFAULT_SCOPES,
  },
  google: {
    label: "Google",
    name: "Google",
    issuer: "https://accounts.google.com",
    scopes: DEFAULT_SCOPES,
  },
  entra: {
    label: "Microsoft Entra ID",
    name: "Microsoft",
    issuer: "",
    scopes: DEFAULT_SCOPES,
  },
  github: {
    label: "GitHub",
    name: "GitHub",
    issuer: "https://github.com",
    scopes: ["read:user", "user:email"],
  },
};

export const TENANT_PLACEHOLDER = "{tenantid}";
const ENTRA = "https://login.microsoftonline.com";
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Issuer and discovery URL of an Entra provider for a directory (tenant) id (single-tenant), or
 * `organizations` / `common` (multi-tenant: the issuer keeps the `{tenantid}` placeholder). `null`
 * for anything else.
 */
export function entraUrls(
  tenant: string,
): { issuer: string; discovery_url: string } | null {
  const t = tenant.trim().toLowerCase();
  if (GUID.test(t)) return { issuer: `${ENTRA}/${t}/v2.0`, discovery_url: "" };
  if (t === "organizations" || t === "common") {
    return {
      issuer: `${ENTRA}/${TENANT_PLACEHOLDER}/v2.0`,
      discovery_url: `${ENTRA}/${t}/v2.0/.well-known/openid-configuration`,
    };
  }
  return null;
}

/** Whether an issuer is a multi-tenant (templated) Entra one. */
export const isMultiTenant = (f: { kind: IdpKind; issuer: string }) =>
  f.kind === "entra" && f.issuer.includes(TENANT_PLACEHOLDER);

/** Editable fields as the inputs hold them (lists as text); the secret is kept apart. */
export interface IdpFormState {
  kind: IdpKind;
  name: string;
  issuer: string;
  discovery_url: string;
  client_id: string;
  client_auth: IdpClientAuth;
  scopes: string;
  policy: IdpPolicy;
  trust_upstream_mfa: boolean;
  mfa_acr: string;
  email_domains: string;
  hosted_domain: string;
  allowed_tenants: string;
  trust_upstream_email: boolean;
  enabled: boolean;
  visible: boolean;
}

/** A new provider's defaults (those the server applies too), or `idp`'s current values. */
export function formState(idp?: IdentityProvider): IdpFormState {
  return {
    kind: idp?.kind ?? "oidc",
    name: idp?.name ?? "",
    issuer: idp?.issuer ?? "",
    discovery_url: idp?.discovery_url ?? "",
    client_id: idp?.client_id ?? "",
    client_auth: idp?.client_auth ?? "post",
    scopes: (idp?.scopes ?? DEFAULT_SCOPES).join(" "),
    policy: idp?.policy ?? "link_only",
    trust_upstream_mfa: idp?.trust_upstream_mfa ?? false,
    mfa_acr: idp?.mfa_acr ?? "",
    email_domains: (idp?.email_domains ?? []).join(", "),
    hosted_domain: idp?.hosted_domain ?? "",
    allowed_tenants: (idp?.allowed_tenants ?? []).join(", "),
    trust_upstream_email: idp?.trust_upstream_email ?? false,
    enabled: idp?.enabled ?? true,
    visible: idp?.visible ?? true,
  };
}

/** Switches a new provider's form to `kind`, filling in the preset's values. */
export function applyPreset(f: IdpFormState, kind: IdpKind): void {
  const presetNames = Object.values(PRESETS).map((p) => p.name);
  const preset = PRESETS[kind];
  Object.assign(f, {
    kind,
    name: presetNames.includes(f.name) ? preset.name : f.name,
    issuer: preset.issuer,
    discovery_url: "",
    scopes: preset.scopes.join(" "),
    client_auth: "post",
    hosted_domain: "",
    allowed_tenants: "",
    trust_upstream_mfa: false,
    mfa_acr: "",
    trust_upstream_email: false,
  });
}

/** Items of a comma- / whitespace-separated list. */
export function words(text: string): string[] {
  return text.split(/[\s,]+/).filter((w) => w.length > 0);
}

const orNull = (s: string) => s.trim() || null;

export function toInput(f: IdpFormState): IdentityProviderInput {
  return {
    kind: f.kind,
    name: f.name.trim(),
    issuer: f.issuer.trim(),
    discovery_url: orNull(f.discovery_url),
    client_id: f.client_id.trim(),
    client_auth: f.client_auth,
    scopes: words(f.scopes),
    policy: f.policy,
    trust_upstream_mfa: f.trust_upstream_mfa,
    mfa_acr: orNull(f.mfa_acr),
    email_domains: words(f.email_domains),
    hosted_domain: f.kind === "google" ? orNull(f.hosted_domain) : null,
    allowed_tenants: isMultiTenant(f) ? words(f.allowed_tenants) : [],
    trust_upstream_email: f.kind !== "github" && f.trust_upstream_email,
    enabled: f.enabled,
    visible: f.visible,
  };
}

/** The fields of `input` that differ from `idp`; `client_secret` is write-only, so it always counts. */
export function changedIdpFields(
  idp: IdentityProvider,
  input: IdentityProviderPatch,
): IdentityProviderPatch {
  return Object.fromEntries(
    Object.entries(input).filter(
      ([key, value]) =>
        key === "client_secret" ||
        JSON.stringify(value) !==
          JSON.stringify(idp[key as keyof IdentityProvider]),
    ),
  );
}

/**
 * Confirmation text when a save repoints the provider (issuer, client ID or
 * discovery URL): the server then unlinks every linked user and, when the
 * issuer or discovery URL moves without a new secret, drops the stored one.
 */
export function relinkWarning(
  diff: IdentityProviderPatch,
  linkedUsers: number,
  hasSecret = false,
): string | null {
  const repoint =
    diff.issuer !== undefined ||
    diff.client_id !== undefined ||
    diff.discovery_url !== undefined;
  if (!repoint) return null;
  const moved = diff.issuer !== undefined || diff.discovery_url !== undefined;
  const newSecret =
    typeof diff.client_secret === "string" && diff.client_secret !== "";
  const parts: string[] = [];
  if (linkedUsers > 0) {
    const who =
      linkedUsers === 1
        ? "the 1 linked user"
        : `all ${linkedUsers} linked users`;
    parts.push(
      `Changing the issuer, client ID or discovery URL unlinks ${who}; they must link again.`,
    );
  }
  if (moved && hasSecret && !newSecret) {
    parts.push(
      "The stored client secret is removed too; enter the secret for the new provider.",
    );
  }
  return parts.length ? parts.join(" ") : null;
}

const norm = (v: string) => v.trim().toLowerCase();

/**
 * Confirmation text when a save lets fewer users in (a new or dropped
 * `allowed_tenants` entry, a new or other `hosted_domain`): the server then
 * removes every membership the provider's group mappings granted. Widening
 * changes nothing, as on the server.
 */
export function narrowingWarning(
  idp: Pick<IdentityProvider, "allowed_tenants" | "hosted_domain">,
  diff: IdentityProviderPatch,
  linkedUsers: number,
): string | null {
  if (linkedUsers <= 0) return null;
  const before = idp.allowed_tenants.map(norm);
  const after = diff.allowed_tenants?.map(norm);
  const tenants =
    after !== undefined &&
    after.length > 0 &&
    (before.length === 0 || before.some((t) => !after.includes(t)));
  const domain =
    typeof diff.hosted_domain === "string" &&
    norm(diff.hosted_domain) !== norm(idp.hosted_domain ?? "");
  if (!tenants && !domain) return null;
  return "Restricting the allowed tenants or hosted domain removes the group memberships this provider's mappings granted; users still allowed get them back at their next sign-in.";
}

/** The lockout sentence for disabling / deleting a provider some users depend on. */
export function lockoutWarning(usersOnlyVia: number): string | null {
  if (usersOnlyVia <= 0) return null;
  const who = usersOnlyVia === 1 ? "1 user" : `${usersOnlyVia} users`;
  return `${who} can sign in only through this provider. They will be locked out until an administrator resets their password or sends an invitation.`;
}
