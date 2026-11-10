---
status: accepted
---

# Roles are defined per tenant kind; this service decides by tier

Tenants of different kinds come from systems with their own roles (a laboratory has
technicians and approvers, a factory has line operators), and some of those systems need
finer permissions than a role name. We replace the closed role enum with a **role catalogue**
in the database: SUPER, SERVICE and GUEST are fixed platform roles, every other role is
defined for one tenant kind and identified by (kind, name), and each role carries one fixed
**tier** (SUPER, SERVICE, ADMIN, MEMBER, GUEST). This service makes every decision of its
own — tenant scope, department access, role ceiling, route guards — from the tier alone.
A role may also grant **permissions** registered for its kind; this service only puts them
in the token (`role`, `tier`, `tenantKind`, `permissions`) and the system that owns each
action checks it. Only SUPER changes the catalogue. LEGACY_ADMIN and LEGACY_USER are merged
into ADMIN and USER, which every kind receives by default.

## Considered Options

- **This service enforces every permission itself**. Rejected: the actions belong to other
  systems; this service would have to know every kind's business rules.
- **Roles per tenant instead of per kind**. Rejected: downstream systems need the same role
  names across all tenants of a kind.
- **Several roles per user (one per system)**. Rejected for the same reason ADR 0003 rejected
  several tenants per user: every scope rule would need a "current role".
- **Per-user permission grants**. Rejected: an access review must be readable as "who holds
  which role"; a user needing other rights gets another role.
- **Catalogue in code**. Rejected: adding a role for another system would need a release of
  this service.

## Consequences

- A role's tier never changes after creation; changing it would silently promote or demote
  every holder. Create a new role instead.
- A user's role must exist in the catalogue of their tenant's kind. Moving a user to a tenant
  of another kind requires a new role; a tenant's kind cannot change while any user (deleted
  ones included) holds a role the new kind lacks; a role or permission still in use cannot be
  removed.
- A change to a role's permissions reaches users at their next token refresh (within 15
  minutes), because refresh rebuilds claims from the database.
- A former LEGACY_ADMIN no longer sees SERVICE users in the user listing, like every ADMIN.
