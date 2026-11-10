-- +goose Up
-- Role catalogue (docs/adr/0006). Roles and permissions are defined per tenant kind; a
-- user's role names a catalogue role of its tenant's kind, or a platform role (SUPER,
-- SERVICE, GUEST) that is not stored here. The service checks a user's role against the
-- catalogue, because the kind lives on the tenant and cannot be a foreign key here.

CREATE TABLE permissions (
    kind        varchar(20)  NOT NULL,
    key         varchar(100) NOT NULL,
    description varchar(255),
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, key),
    CONSTRAINT permissions_kind_check CHECK (kind IN ('HOSPITAL', 'LAB', 'FACTORY', 'CLINIC', 'PHARMACY', 'OTHER'))
);

CREATE TABLE roles (
    kind        varchar(20)  NOT NULL,
    name        varchar(50)  NOT NULL,
    tier        varchar(10)  NOT NULL,
    description varchar(255),
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, name),
    CONSTRAINT roles_kind_check CHECK (kind IN ('HOSPITAL', 'LAB', 'FACTORY', 'CLINIC', 'PHARMACY', 'OTHER')),
    -- SUPER and SERVICE are platform tiers only.
    CONSTRAINT roles_tier_check CHECK (tier IN ('ADMIN', 'MEMBER', 'GUEST')),
    CONSTRAINT roles_not_platform CHECK (name NOT IN ('SUPER', 'SERVICE', 'GUEST'))
);

-- Removing a role drops what it grants; a permission still granted cannot be removed.
CREATE TABLE role_permissions (
    kind           varchar(20)  NOT NULL,
    role_name      varchar(50)  NOT NULL,
    permission_key varchar(100) NOT NULL,
    PRIMARY KEY (kind, role_name, permission_key),
    FOREIGN KEY (kind, role_name) REFERENCES roles (kind, name) ON DELETE CASCADE,
    FOREIGN KEY (kind, permission_key) REFERENCES permissions (kind, key) ON DELETE RESTRICT
);

CREATE INDEX role_permissions_permission_idx ON role_permissions (kind, permission_key);

-- Every kind starts with the two roles the closed role list had.
INSERT INTO roles (kind, name, tier, description)
SELECT k.kind, r.name, r.tier, r.description
FROM (VALUES ('HOSPITAL'), ('LAB'), ('FACTORY'), ('CLINIC'), ('PHARMACY'), ('OTHER')) AS k (kind)
CROSS JOIN (VALUES ('ADMIN', 'ADMIN', 'Tenant administrator'),
                   ('USER', 'MEMBER', 'Tenant member')) AS r (name, tier, description);

-- LEGACY_ADMIN and LEGACY_USER are merged into ADMIN and USER.
ALTER TABLE users DROP CONSTRAINT users_role_check;
ALTER TABLE users ALTER COLUMN role TYPE varchar(50);
UPDATE users SET role = 'ADMIN' WHERE role = 'LEGACY_ADMIN';
UPDATE users SET role = 'USER' WHERE role = 'LEGACY_USER';
CREATE INDEX users_role_idx ON users (role);

-- +goose Down
-- The merge cannot be undone: which ADMIN was a LEGACY_ADMIN is not recorded. Users keep
-- ADMIN/USER, which the old check accepts; any other catalogue role must be changed first.
DROP INDEX users_role_idx;
ALTER TABLE users ALTER COLUMN role TYPE varchar(20);
ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('SUPER', 'SERVICE', 'ADMIN', 'LEGACY_ADMIN', 'USER', 'LEGACY_USER', 'GUEST'));
DROP TABLE role_permissions;
DROP TABLE roles;
DROP TABLE permissions;
