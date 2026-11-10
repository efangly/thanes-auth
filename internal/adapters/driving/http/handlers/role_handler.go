package handlers

import (
	"github.com/efangly/smtrack-authentication/internal/adapters/driving/http/dto"
	"github.com/efangly/smtrack-authentication/internal/core/domain"
	"github.com/efangly/smtrack-authentication/internal/core/ports"
	"github.com/gofiber/fiber/v3"
)

// RoleHandler handles the role catalogue: /auth/role and /auth/permission.
type RoleHandler struct {
	roleService ports.RoleService
}

// NewRoleHandler creates a new role catalogue handler.
func NewRoleHandler(roleService ports.RoleService) *RoleHandler {
	return &RoleHandler{roleService: roleService}
}

func unauthorized(c fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(dto.FailResponse("Unauthorized"))
}

// FindRoles lists the catalogue roles, optionally of one kind (?kind=LAB).
func (h *RoleHandler) FindRoles(c fiber.Ctx) error {
	caller := getCaller(c)
	if caller == nil {
		return unauthorized(c)
	}
	roles, err := h.roleService.FindRoles(c.Context(), domain.TenantKind(c.Query("kind")), caller)
	if err != nil {
		return serviceError(c, fiber.StatusBadRequest, err)
	}
	return c.Status(fiber.StatusOK).JSON(dto.SuccessResponse(dto.FromRoles(roles)))
}

// FindRole returns one catalogue role.
func (h *RoleHandler) FindRole(c fiber.Ctx) error {
	caller := getCaller(c)
	if caller == nil {
		return unauthorized(c)
	}
	role, err := h.roleService.FindRole(c.Context(), domain.TenantKind(c.Params("kind")), domain.Role(c.Params("name")), caller)
	if err != nil {
		return serviceError(c, fiber.StatusNotFound, err)
	}
	return c.Status(fiber.StatusOK).JSON(dto.SuccessResponse(dto.FromRole(role)))
}

// CreateRole adds a role to a kind's catalogue.
func (h *RoleHandler) CreateRole(c fiber.Ctx) error {
	caller := getCaller(c)
	if caller == nil {
		return unauthorized(c)
	}
	var req dto.CreateRoleRequest
	if err := c.Bind().Body(&req); err != nil {
		return badRequest(c, err)
	}
	role, err := h.roleService.CreateRole(c.Context(), req.ToRole(), caller)
	if err != nil {
		return serviceError(c, fiber.StatusBadRequest, err)
	}
	return c.Status(fiber.StatusCreated).JSON(dto.SuccessResponse(dto.FromRole(role)))
}

// UpdateRole changes a role's description or permissions.
func (h *RoleHandler) UpdateRole(c fiber.Ctx) error {
	caller := getCaller(c)
	if caller == nil {
		return unauthorized(c)
	}
	var req dto.UpdateRoleRequest
	if err := c.Bind().Body(&req); err != nil {
		return badRequest(c, err)
	}
	role, err := h.roleService.UpdateRole(c.Context(), domain.TenantKind(c.Params("kind")), domain.Role(c.Params("name")), req.ToPatch(), caller)
	if err != nil {
		return serviceError(c, fiber.StatusBadRequest, err)
	}
	return c.Status(fiber.StatusOK).JSON(dto.SuccessResponse(dto.FromRole(role)))
}

// RemoveRole deletes a role nobody holds.
func (h *RoleHandler) RemoveRole(c fiber.Ctx) error {
	caller := getCaller(c)
	if caller == nil {
		return unauthorized(c)
	}
	if err := h.roleService.RemoveRole(c.Context(), domain.TenantKind(c.Params("kind")), domain.Role(c.Params("name")), caller); err != nil {
		return serviceError(c, fiber.StatusBadRequest, err)
	}
	return c.Status(fiber.StatusOK).JSON(dto.SuccessResponse("Role removed"))
}

// FindPermissions lists the catalogue permissions, optionally of one kind.
func (h *RoleHandler) FindPermissions(c fiber.Ctx) error {
	caller := getCaller(c)
	if caller == nil {
		return unauthorized(c)
	}
	permissions, err := h.roleService.FindPermissions(c.Context(), domain.TenantKind(c.Query("kind")), caller)
	if err != nil {
		return serviceError(c, fiber.StatusBadRequest, err)
	}
	return c.Status(fiber.StatusOK).JSON(dto.SuccessResponse(dto.FromPermissions(permissions)))
}

// CreatePermission registers a permission for a kind.
func (h *RoleHandler) CreatePermission(c fiber.Ctx) error {
	caller := getCaller(c)
	if caller == nil {
		return unauthorized(c)
	}
	var req dto.CreatePermissionRequest
	if err := c.Bind().Body(&req); err != nil {
		return badRequest(c, err)
	}
	permission, err := h.roleService.CreatePermission(c.Context(), req.ToPermission(), caller)
	if err != nil {
		return serviceError(c, fiber.StatusBadRequest, err)
	}
	return c.Status(fiber.StatusCreated).JSON(dto.SuccessResponse(dto.FromPermission(permission)))
}

// UpdatePermission changes a permission's description.
func (h *RoleHandler) UpdatePermission(c fiber.Ctx) error {
	caller := getCaller(c)
	if caller == nil {
		return unauthorized(c)
	}
	var req dto.UpdatePermissionRequest
	if err := c.Bind().Body(&req); err != nil {
		return badRequest(c, err)
	}
	permission, err := h.roleService.UpdatePermission(c.Context(), domain.TenantKind(c.Params("kind")), c.Params("key"), req.ToPatch(), caller)
	if err != nil {
		return serviceError(c, fiber.StatusBadRequest, err)
	}
	return c.Status(fiber.StatusOK).JSON(dto.SuccessResponse(dto.FromPermission(permission)))
}

// RemovePermission deletes a permission no role grants.
func (h *RoleHandler) RemovePermission(c fiber.Ctx) error {
	caller := getCaller(c)
	if caller == nil {
		return unauthorized(c)
	}
	if err := h.roleService.RemovePermission(c.Context(), domain.TenantKind(c.Params("kind")), c.Params("key"), caller); err != nil {
		return serviceError(c, fiber.StatusBadRequest, err)
	}
	return c.Status(fiber.StatusOK).JSON(dto.SuccessResponse("Permission removed"))
}
