# SMtrack Authentication

Who may use the SMtrack platform, which tenant and departments they belong to, and what each
of them is allowed to see and change.

## Organisation

**Tenant**:
A customer organisation using SMtrack (a hospital, laboratory, factory, clinic, …), and the
unit of tenancy. Every user belongs to exactly one tenant, and every department belongs to
exactly one tenant.
_Avoid_: Hospital (as the general term), organisation, site, customer

**Tenant kind**:
What sort of organisation a tenant is: hospital, laboratory, factory, clinic, pharmacy or
other. It chooses the default labels shown to that tenant's users and which roles and
permissions its users can be given, but it never changes what a tier allows.
_Avoid_: Tenant type, category

**Department**:
A subdivision of a tenant where monitored devices live (a ward, a production line, a lab
bench). A user may be linked to any number of departments of their own tenant, or none.
Departments are flat; one does not contain another.
_Avoid_: Ward (as the general term), unit, room, team

**Label profile**:
A tenant's own names for "tenant" and "department" in each language, such as "Factory" and
"Line", shown by the frontend to that tenant's users. Labels are display text only and never
affect access. A tenant without a profile gets the defaults for its kind.
_Avoid_: Alias, translation, custom name, theme

**Hidden tenant**:
A tenant that only SUPER can see, used internally for testing. It cannot be chosen when
registering.
_Avoid_: Development hospital, test tenant, sandbox

**Legacy**:
A flag on a tenant or department that was migrated from the earlier hospital/ward model and
still has its devices managed by the legacy service.
_Avoid_: Old, deprecated

## People and access

**User**:
An account that can sign in. It has a username, a role, a status, one tenant and any number
of departments within it.
_Avoid_: Account (for the record), member, login

**Actor**:
The user performing the current request, as identified by their access token.
_Avoid_: Principal, JWT payload, current user

**Role**:
The single named job a user holds, such as ADMIN, USER or a laboratory's "Lab technician".
It is either a platform role or a role defined for one tenant kind, and it always has
exactly one tier.
_Avoid_: Group, position, job title

**Platform role**:
A role that exists the same way for every tenant kind: SUPER, SERVICE and GUEST.
_Avoid_: System role, built-in role

**Tier**:
The fixed level of authority a role carries, and the only thing this service looks at when
deciding what someone may do here: SUPER, SERVICE, ADMIN, MEMBER or GUEST. A role's tier
never changes.
_Avoid_: Level, rank, role (when the tier is meant)

**Permission**:
A named action in another SMtrack system, such as approving a lab result, that a role grants.
Permissions are defined per tenant kind, granted only through roles, and checked by the
system that owns the action, never by this service.
_Avoid_: Right, privilege, scope, role

**Role catalogue**:
The roles and permissions defined for each tenant kind, and which permissions each role
grants. Only SUPER may change it.
_Avoid_: Role list, role config

**Guest**:
The platform role every self-registered user starts with; it can see little until an admin
promotes it.
_Avoid_: Anonymous, visitor, pending user

**Admin tier**:
The tiers allowed to act on users other than themselves: SUPER, SERVICE and ADMIN.
_Avoid_: Admins (when SERVICE or SUPER are meant too), staff

**Tenant-scoped admin**:
A user whose role has the ADMIN tier: admin tier, but confined to their own tenant.
_Avoid_: Local admin, hospital admin

**Role ceiling**:
The highest tier an actor may give to a user, which is also the highest tier of a user the
actor may change or delete. SUPER may reach any tier; SERVICE any but SUPER; a tenant-scoped
admin only MEMBER and GUEST roles of their own tenant's kind, whatever permissions those
roles grant. Nobody may change their own role.
_Avoid_: Role hierarchy, rank

**Tenant scope**:
The tenants whose records an actor may see or change. System-wide for SUPER and SERVICE, the
actor's own tenant for everyone else. Records outside it are treated as if they do not exist.
_Avoid_: Visibility, permissions, data scope

**Department access**:
Which departments of their tenant an actor can see. A tenant-scoped admin sees all of them;
any lower tier sees only the departments they are linked to.
_Avoid_: Department permission, membership

**Status**:
Whether a user is active. An inactive user cannot sign in or renew their session.
_Avoid_: Enabled, locked, banned

**Lockout**:
A temporary refusal to sign in to a username after repeated wrong passwords. It looks the
same as a wrong password to the caller.
_Avoid_: Ban, suspension

## Record keeping

**Soft delete**:
Removing a user, tenant or department from every normal view and from sign-in while keeping
the record so it can be restored. A deleted user's username stays reserved.
_Avoid_: Archive, deactivate (that is Status)

**Restore**:
Bringing a soft-deleted record back with its former status and links.
_Avoid_: Undelete, recover

**Purge**:
Permanently erasing records that have been soft-deleted for longer than the retention period.
It is a deliberate operator action, never automatic.
_Avoid_: Hard delete, cleanup

**Audit log**:
An append-only record of security-relevant events: who created, updated, deleted, restored or
purged a user, department or tenant and what changed, and sign-ins, failed sign-ins,
password resets and refused accesses. It cannot be edited or deleted, and it is not divided
by tenant.
_Avoid_: History, activity log, event log

**Access review**:
A report of every user with their role, status, tenant, departments and last sign-in, used to
check that people still hold only the access they need.
_Avoid_: Audit (that is the Audit log), user export

**Picture**:
The image of a user or a tenant. It is stored encrypted, and anyone holding its address can view it.
_Avoid_: Avatar, logo, photo
