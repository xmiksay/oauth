// Upstream OIDC identity providers (`/api/v1/identity-providers` on the tenant's host).
import { query } from './client'
import { p, t } from './management'
import type {
  IdentityProvider,
  IdentityProviderDetail,
  IdentityProviderInput,
  IdentityProviderPatch,
  IdpGroupMapping,
  IdpGroupMappingInput,
  PageQuery,
  Paged,
} from './types'

export const identityProviders = {
  // The endpoint pages but has no search.
  list: (q: PageQuery = {}) =>
    t.get<Paged<IdentityProvider>>(
      `identity-providers${query({ limit: q.limit, cursor: q.cursor })}`,
    ),
  get: (id: string) => t.get<IdentityProviderDetail>(p`identity-providers/${id}`),
  create: (body: IdentityProviderInput) => t.post<IdentityProvider>('identity-providers', body),
  update: (id: string, body: IdentityProviderPatch) =>
    t.patch<IdentityProviderDetail>(p`identity-providers/${id}`, body),
  remove: (id: string) => t.del(p`identity-providers/${id}`),
  mappings: (id: string, q: PageQuery = {}) =>
    t.get<Paged<IdpGroupMapping>>(
      `${p`identity-providers/${id}/group-mappings`}${query({ limit: q.limit, cursor: q.cursor })}`,
    ),
  addMapping: (id: string, body: IdpGroupMappingInput) =>
    t.post<IdpGroupMapping>(p`identity-providers/${id}/group-mappings`, body),
  removeMapping: (id: string, mappingId: string) =>
    t.del(p`identity-providers/${id}/group-mappings/${mappingId}`),
}
