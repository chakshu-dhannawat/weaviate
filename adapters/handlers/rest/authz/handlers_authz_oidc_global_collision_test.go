//                           _       _
// __      _____  __ ___   ___  __ _| |_ ___
// \ \ /\ / / _ \/ _` \ \ / / |/ _` | __/ _ \
//  \ V  V /  __/ (_| |\ V /| | (_| | ||  __/
//   \_/\_/ \___|\__,_| \_/ |_|\__,_|\__\___|
//
//  Copyright © 2016 - 2026 Weaviate B.V. All rights reserved.
//
//  CONTACT: hello@weaviate.io
//

package authz

import (
	"testing"

	"github.com/go-openapi/runtime/middleware"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/weaviate/weaviate/adapters/handlers/rest/operations/authz"
	"github.com/weaviate/weaviate/entities/models"
	"github.com/weaviate/weaviate/usecases/auth/authentication"
	"github.com/weaviate/weaviate/usecases/auth/authorization"
	"github.com/weaviate/weaviate/usecases/auth/authorization/rbac/rbacconf"
	"github.com/weaviate/weaviate/usecases/config"
)

// collisionHandler wires a permissive handler whose store optionally holds a
// slotted global OIDC user "oidc::customer1:carol" — the twin that collides
// with the namespaced target id "customer1:carol".
func collisionHandler(t *testing.T, twinExists bool) (*authZHandlers, *MockControllerAndGetUsers) {
	t.Helper()
	authorizer := authorization.NewMockAuthorizer(t)
	authorizer.On("Authorize", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	authorizer.On("AuthorizeSilent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	controller := NewMockControllerAndGetUsers(t)
	controller.On("GetRoles", mock.Anything).Return(map[string][]authorization.Policy{"customRole": {}}, nil).Maybe()
	controller.On("GetRoles", mock.Anything, mock.Anything).Return(map[string][]authorization.Policy{"customRole": {}}, nil).Maybe()
	controller.On("AddRolesForUser", mock.Anything, mock.Anything).Return(nil).Maybe()
	controller.On("RevokeRolesForUser", mock.Anything, mock.Anything).Return(nil).Maybe()

	twin := map[string][]authorization.Policy{}
	if twinExists {
		twin = map[string][]authorization.Policy{"admin": {}}
	}
	controller.On("GetRolesForUserOrGroup", ":customer1:carol", authentication.AuthTypeOIDC, false).Return(twin, nil).Maybe()
	// The namespaced subject read reached only when the guard does not fire.
	controller.On("GetRolesForUserOrGroup", "customer1:carol", authentication.AuthTypeOIDC, false).Return(map[string][]authorization.Policy{}, nil).Maybe()

	logger, _ := test.NewNullLogger()
	h := &authZHandlers{
		authorizer:        authorizer,
		controller:        controller,
		logger:            logger,
		rbacconfig:        rbacconf.Config{Enabled: true},
		oidcConfigs:       config.OIDC{Enabled: true},
		namespacesEnabled: true,
	}
	return h, controller
}

// TestOIDCGlobalCollisionRejectsAmbiguousTarget pins the guardrail: when a
// global caller targets a colon-bearing OIDC id that also matches an existing
// global OIDC user of that literal name, assign/revoke/read return 400 rather
// than silently landing on (or missing) the namespaced twin.
func TestOIDCGlobalCollisionRejectsAmbiguousTarget(t *testing.T) {
	global := &models.Principal{Username: "admin", UserType: models.UserTypeInputOidc}
	const target = "customer1:carol"

	tests := []struct {
		name        string
		invoke      func(h *authZHandlers) middleware.Responder
		check       func(t *testing.T, res middleware.Responder)
		writeMethod string // controller write that must not run; "" for the read path
	}{
		{
			name: "assign",
			invoke: func(h *authZHandlers) middleware.Responder {
				return h.assignRoleToUser(authz.AssignRoleToUserParams{HTTPRequest: req, ID: target, Body: authz.AssignRoleToUserBody{Roles: []string{"customRole"}, UserType: models.UserTypeInputOidc}}, global)
			},
			check: func(t *testing.T, res middleware.Responder) {
				br, ok := res.(*authz.AssignRoleToUserBadRequest)
				require.True(t, ok, "got %T", res)
				require.Contains(t, br.Payload.Error[0].Message, "ADMIN_USERS")
			},
			writeMethod: "AddRolesForUser",
		},
		{
			name: "revoke",
			invoke: func(h *authZHandlers) middleware.Responder {
				return h.revokeRoleFromUser(authz.RevokeRoleFromUserParams{HTTPRequest: req, ID: target, Body: authz.RevokeRoleFromUserBody{Roles: []string{"customRole"}, UserType: models.UserTypeInputOidc}}, global)
			},
			check: func(t *testing.T, res middleware.Responder) {
				br, ok := res.(*authz.RevokeRoleFromUserBadRequest)
				require.True(t, ok, "got %T", res)
				require.Contains(t, br.Payload.Error[0].Message, "ADMIN_USERS")
			},
			writeMethod: "RevokeRolesForUser",
		},
		{
			name: "getRolesForUser",
			invoke: func(h *authZHandlers) middleware.Responder {
				falseP := false
				return h.getRolesForUser(authz.GetRolesForUserParams{HTTPRequest: req, ID: target, UserType: string(models.UserTypeInputOidc), IncludeFullRoles: &falseP}, global)
			},
			check: func(t *testing.T, res middleware.Responder) {
				br, ok := res.(*authz.GetRolesForUserBadRequest)
				require.True(t, ok, "got %T", res)
				require.Contains(t, br.Payload.Error[0].Message, "ADMIN_USERS")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, controller := collisionHandler(t, true)
			res := tt.invoke(h)
			tt.check(t, res)
			if tt.writeMethod != "" {
				controller.AssertNotCalled(t, tt.writeMethod, mock.Anything, mock.Anything)
			}
		})
	}
}

// TestOIDCGlobalCollisionAllowsWhenNoTwin pins the discriminator: with no
// slotted global twin in the store, the same colon-bearing target is an ordinary
// namespaced user and the write proceeds against oidc:customer1:carol.
func TestOIDCGlobalCollisionAllowsWhenNoTwin(t *testing.T) {
	global := &models.Principal{Username: "admin", UserType: models.UserTypeInputOidc}
	h, controller := collisionHandler(t, false)
	res := h.assignRoleToUser(authz.AssignRoleToUserParams{HTTPRequest: req, ID: "customer1:carol", Body: authz.AssignRoleToUserBody{Roles: []string{"customRole"}, UserType: models.UserTypeInputOidc}}, global)
	_, ok := res.(*authz.AssignRoleToUserOK)
	require.True(t, ok, "got %T", res)
	controller.AssertCalled(t, "AddRolesForUser", "oidc:customer1:carol", []string{"customRole"})
}

// TestOIDCGlobalCollisionNamespacedCallerUnaffected pins that the guard never
// fires for a namespaced caller: its id is force-qualified into its own
// namespace and can never address the global slot, so managing its own user
// proceeds without any twin lookup — the short-circuit is independent of store
// contents.
func TestOIDCGlobalCollisionNamespacedCallerUnaffected(t *testing.T) {
	h, controller := nsAssignHandler(t, "customer1")
	h.oidcConfigs = config.OIDC{Enabled: true}
	principal := &models.Principal{Username: "customer1:admin", UserType: "oidc", Namespace: "customer1"}
	res := h.assignRoleToUser(authz.AssignRoleToUserParams{HTTPRequest: req, ID: "carol", Body: authz.AssignRoleToUserBody{Roles: []string{"editor"}, UserType: models.UserTypeInputOidc}}, principal)
	_, ok := res.(*authz.AssignRoleToUserOK)
	require.True(t, ok, "got %T", res)
	controller.AssertCalled(t, "AddRolesForUser", "oidc:customer1:carol", []string{"customer1:editor"})
	controller.AssertNotCalled(t, "GetRolesForUserOrGroup", mock.Anything, mock.Anything, mock.Anything)
}
