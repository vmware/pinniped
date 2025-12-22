// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package credentialrequest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/sclevine/spec"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/utils/ptr"

	loginapi "go.pinniped.dev/generated/latest/apis/concierge/login"
	"go.pinniped.dev/internal/cert"
	"go.pinniped.dev/internal/clientcertissuer"
	"go.pinniped.dev/internal/mocks/mockcredentialrequest"
	"go.pinniped.dev/internal/mocks/mockissuer"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
)

func TestNew(t *testing.T) {
	r := NewREST(nil, nil, schema.GroupResource{Group: "bears", Resource: "panda"}, nil)
	require.NotNil(t, r)
	require.False(t, r.NamespaceScoped())
	require.Equal(t, []string{"pinniped"}, r.Categories())
	require.Equal(t, "tokencredentialrequest", r.GetSingularName())
	require.IsType(t, &loginapi.TokenCredentialRequest{}, r.New())
	require.IsType(t, &loginapi.TokenCredentialRequestList{}, r.NewList())

	ctx := context.Background()

	// check the simple invariants of our no-op list
	list, err := r.List(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, list)
	require.IsType(t, &loginapi.TokenCredentialRequestList{}, list)
	require.Equal(t, "0", list.(*loginapi.TokenCredentialRequestList).ResourceVersion)
	require.NotNil(t, list.(*loginapi.TokenCredentialRequestList).Items)
	require.Len(t, list.(*loginapi.TokenCredentialRequestList).Items, 0)

	// make sure we can turn lists into tables if needed
	table, err := r.ConvertToTable(ctx, list, nil)
	require.NoError(t, err)
	require.NotNil(t, table)
	require.Equal(t, "0", table.ResourceVersion)
	require.Nil(t, table.Rows)

	// exercise group resource - force error by passing a runtime.Object that does not have an embedded object meta
	_, err = r.ConvertToTable(ctx, &metav1.APIGroup{}, nil)
	require.Error(t, err, "the resource panda.bears does not support being converted to a Table")
}

func tokenToHash(tok string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(tok)))
}

func TestCreate(t *testing.T) {
	spec.Run(t, "create", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var ctrl *gomock.Controller
		var auditLogger plog.AuditLogger
		var actualAuditLog *bytes.Buffer
		var fakeNow time.Time
		var wantAuditLog []testutil.WantedAuditLog

		it.Before(func() {
			r = require.New(t)
			ctrl = gomock.NewController(t)
			auditLogger, actualAuditLog = plog.TestAuditLogger(t)
			fakeNow = time.Date(2024, time.September, 12, 4, 25, 56, 778899, time.UTC)
		})

		it.After(func() {
			testutil.CompareAuditLogs(t, wantAuditLog, actualAuditLog.String())
			ctrl.Finish()
		})

		it("CreateSucceedsWhenGivenATokenAndTheAuthenticatorAuthenticatesTheToken", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req).
				Return(&user.DefaultInfo{
					Name:   "test-user",
					Groups: []string{"test-group-1", "test-group-2"},
				}, nil)

			clientCertIssuer := mockissuer.NewMockClientCertIssuer(ctrl)
			clientCertIssuer.EXPECT().IssueClientCertPEM(
				"test-user",
				[]string{"test-group-1", "test-group-2"},
				nil,
				5*time.Minute,
			).Return(&cert.PEM{
				CertPEM:   []byte("test-cert"),
				KeyPEM:    []byte("test-key"),
				NotBefore: fakeNow.Add(-5 * time.Minute),
				NotAfter:  fakeNow.Add(5 * time.Minute),
			}, nil)

			storage := NewREST(requestAuthenticator, clientCertIssuer, schema.GroupResource{}, auditLogger)

			response, err := callCreate(storage, req)

			r.NoError(err)
			r.IsType(&loginapi.TokenCredentialRequest{}, response)

			r.Equal(response, &loginapi.TokenCredentialRequest{
				Status: loginapi.TokenCredentialRequestStatus{
					Credential: &loginapi.ClusterCredential{
						ExpirationTimestamp:   metav1.NewTime(fakeNow.Add(5 * time.Minute).UTC()),
						ClientCertificateData: "test-cert",
						ClientKeyData:         "test-key",
					},
				},
			})

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Authenticated User", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"issuedClientCert": map[string]any{
						"notBefore": "2024-09-12T04:20:56Z", // this is fakeNow - 5 minutes in UTC
						"notAfter":  "2024-09-12T04:30:56Z", // this is fakeNow + 5 minutes in UTC
					},
					"personalInfo": map[string]any{
						"username": "test-user",
						"groups":   []any{"test-group-1", "test-group-2"},
						"extras":   map[string]any{},
					},
				}),
			}
		})

		it("CreateFailsWithValidTokenWhenCertIssuerFails", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req).
				Return(&user.DefaultInfo{
					Name:   "test-user",
					Groups: []string{"test-group-1", "test-group-2"},
				}, nil)

			clientCertIssuer := mockissuer.NewMockClientCertIssuer(ctrl)
			clientCertIssuer.EXPECT().
				IssueClientCertPEM(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil, fmt.Errorf("some certificate authority error"))

			storage := NewREST(requestAuthenticator, clientCertIssuer, schema.GroupResource{}, auditLogger)

			response, err := callCreate(storage, req)
			requireSuccessfulResponseWithAuthenticationFailureMessage(t, err, response)

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Unexpected Error", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"reason": "cert issuer returned an error",
					"err":    "some certificate authority error",
				}),
			}
		})

		it("CreateSucceedsWithAnUnauthenticatedStatusWhenGivenATokenAndTheAuthenticatorReturnsNilUser", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req).Return(nil, nil)

			storage := NewREST(requestAuthenticator, nil, schema.GroupResource{}, auditLogger)

			response, err := callCreate(storage, req)

			requireSuccessfulResponseWithAuthenticationFailureMessage(t, err, response)

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Authentication Failed", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"reason": "auth rejected by authenticator",
				}),
			}
		})

		it("CreateSucceedsWithAnUnauthenticatedStatusWhenAuthenticatorFails", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req).
				Return(nil, errors.New("some authentication error"))

			storage := NewREST(requestAuthenticator, nil, schema.GroupResource{}, auditLogger)

			response, err := callCreate(storage, req)

			requireSuccessfulResponseWithAuthenticationFailureMessage(t, err, response)

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Unexpected Error", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"reason": "authenticator returned an error",
					"err":    "some authentication error",
				}),
			}
		})

		it("CreateSucceedsWithAnUnauthenticatedStatusWhenAuthenticatorReturnsAnEmptyUsername", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req).
				Return(&user.DefaultInfo{Name: "", UID: "test-uid"}, nil)

			storage := NewREST(requestAuthenticator, nil, schema.GroupResource{}, auditLogger)

			response, err := callCreate(storage, req)

			requireSuccessfulResponseWithAuthenticationFailureMessage(t, err, response)

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Unsupported UserInfo", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"reason":              "unsupported value in userInfo returned by authenticator",
					"err":                 "empty username is not allowed",
					"userInfoExtrasCount": float64(0),
					"personalInfo": map[string]any{
						"userInfoName": "",
						"userInfoUID":  "test-uid",
					},
				}),
			}
		})

		it("CreateSucceedsWithAnUnauthenticatedStatusWhenAuthenticatorReturnsAUserWithUID", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req).
				Return(&user.DefaultInfo{
					Name:   "test-user",
					UID:    "test-uid",
					Groups: []string{"test-group-1", "test-group-2"},
				}, nil)

			storage := NewREST(requestAuthenticator, nil, schema.GroupResource{}, auditLogger)

			response, err := callCreate(storage, req)

			requireSuccessfulResponseWithAuthenticationFailureMessage(t, err, response)

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Unsupported UserInfo", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"reason":              "unsupported value in userInfo returned by authenticator",
					"err":                 "UIDs are not supported",
					"userInfoExtrasCount": float64(0),
					"personalInfo": map[string]any{
						"userInfoName": "test-user",
						"userInfoUID":  "test-uid",
					},
				}),
			}
		})

		it("CreateSucceedsWhenAuthenticatorReturnsAUserWithExtras", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req).
				Return(&user.DefaultInfo{
					Name:   "test-user",
					Groups: []string{"test-group-1", "test-group-2"},
					Extra: map[string][]string{
						"authentication.kubernetes.io/credential-id": {"test-val-1", "test-val-2"},
						"example.com/extra1":                         {"test-val-a"},
						"example.com/extra2":                         {"test-val-b"},
					},
				}, nil)

			clientCertIssuer := mockissuer.NewMockClientCertIssuer(ctrl)
			clientCertIssuer.EXPECT().IssueClientCertPEM(
				"test-user",
				[]string{"test-group-1", "test-group-2"},
				[]string{
					"authentication.kubernetes.io/credential-id=test-val-1",
					"authentication.kubernetes.io/credential-id=test-val-2",
					"example.com/extra1=test-val-a",
					"example.com/extra2=test-val-b",
				},
				5*time.Minute,
			).Return(&cert.PEM{
				CertPEM:   []byte("test-cert"),
				KeyPEM:    []byte("test-key"),
				NotBefore: fakeNow.Add(-5 * time.Minute),
				NotAfter:  fakeNow.Add(5 * time.Minute),
			}, nil)

			storage := NewREST(requestAuthenticator, clientCertIssuer, schema.GroupResource{}, auditLogger)

			response, err := callCreate(storage, req)

			r.NoError(err)
			r.IsType(&loginapi.TokenCredentialRequest{}, response)

			r.Equal(response, &loginapi.TokenCredentialRequest{
				Status: loginapi.TokenCredentialRequestStatus{
					Credential: &loginapi.ClusterCredential{
						ExpirationTimestamp:   metav1.NewTime(fakeNow.Add(5 * time.Minute).UTC()),
						ClientCertificateData: "test-cert",
						ClientKeyData:         "test-key",
					},
				},
			})

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Authenticated User", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"issuedClientCert": map[string]any{
						"notBefore": "2024-09-12T04:20:56Z", // this is fakeNow - 5 minutes in UTC
						"notAfter":  "2024-09-12T04:30:56Z", // this is fakeNow + 5 minutes in UTC
					},
					"personalInfo": map[string]any{
						"username": "test-user",
						"groups":   []any{"test-group-1", "test-group-2"},
						"extras": map[string]any{
							"authentication.kubernetes.io/credential-id": []any{"test-val-1", "test-val-2"},
							"example.com/extra1":                         []any{"test-val-a"},
							"example.com/extra2":                         []any{"test-val-b"},
						},
					},
				}),
			}
		})

		it("CreateSucceedsWithAnUnauthenticatedStatusWhenWebhookReturnsAUserWithInvalidExtraKey", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req).
				Return(&user.DefaultInfo{
					Name:   "test-user",
					Groups: []string{"test-group-1", "test-group-2"},
					Extra:  map[string][]string{"key-name": {"test-val-1", "test-val-2"}},
				}, nil)

			storage := NewREST(requestAuthenticator, nil, schema.GroupResource{}, auditLogger)

			response, err := callCreate(storage, req)

			requireSuccessfulResponseWithAuthenticationFailureMessage(t, err, response)

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Unsupported UserInfo", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"reason":              "unsupported value in userInfo returned by authenticator",
					"err":                 `authenticator returned illegal userInfo extra key(s): userInfo extra key "key-name": Invalid value: "key-name": must be a domain-prefixed path (such as "acme.io/foo")`,
					"userInfoExtrasCount": float64(1),
					"personalInfo": map[string]any{
						"userInfoName": "test-user",
						"userInfoUID":  "",
					},
				}),
			}
		})

		it("CreateFailsWhenGivenTheWrongInputType", func() {
			notACredentialRequest := runtime.Unknown{}
			response, err := NewREST(nil, nil, schema.GroupResource{}, auditLogger).Create(
				genericapirequest.NewContext(),
				&notACredentialRequest,
				rest.ValidateAllObjectFunc,
				&metav1.CreateOptions{})

			requireAPIError(t, response, err, apierrors.IsBadRequest, "not a TokenCredentialRequest")
		})

		it("CreateFailsWhenTokenValueIsEmptyInRequest", func() {
			storage := NewREST(nil, nil, schema.GroupResource{}, auditLogger)
			response, err := callCreate(storage, credentialRequest(loginapi.TokenCredentialRequestSpec{
				Token: "",
			}))

			requireAPIError(t, response, err, apierrors.IsInvalid,
				`.pinniped.dev "request name" is invalid: spec.token.value: Required value: token must be supplied`)
		})

		it("CreateFailsWhenValidationFails", func() {
			storage := NewREST(nil, nil, schema.GroupResource{}, auditLogger)
			response, err := storage.Create(
				context.Background(),
				validCredentialRequest(),
				func(ctx context.Context, obj runtime.Object) error {
					return fmt.Errorf("some validation error")
				},
				&metav1.CreateOptions{})
			r.Nil(response)
			r.EqualError(err, "some validation error")
		})

		it("CreateDoesNotAllowValidationFunctionToMutateRequest", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req.DeepCopy()).
				Return(&user.DefaultInfo{Name: "test-user"}, nil)

			fakeReqContext := audit.WithAuditContext(context.Background())
			audit.WithAuditID(fakeReqContext, "fake-audit-id")

			storage := NewREST(requestAuthenticator, successfulIssuer(ctrl, fakeNow), schema.GroupResource{}, auditLogger)
			response, err := storage.Create(
				fakeReqContext,
				req,
				func(ctx context.Context, obj runtime.Object) error {
					credentialRequest, _ := obj.(*loginapi.TokenCredentialRequest)
					credentialRequest.Spec.Token = "foobaz"
					return nil
				},
				&metav1.CreateOptions{})
			r.NoError(err)
			r.NotEmpty(response)

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Authenticated User", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"issuedClientCert": map[string]any{
						"notBefore": "2024-09-12T04:20:56Z", // this is fakeNow - 5 minutes in UTC
						"notAfter":  "2024-09-12T04:30:56Z", // this is fakeNow + 5 minutes in UTC
					},
					"personalInfo": map[string]any{
						"username": "test-user",
						"groups":   []any{},
						"extras":   map[string]any{},
					},
				}),
			}
		})

		it("CreateDoesNotAllowValidationFunctionToSeeTheActualRequestToken", func() {
			req := validCredentialRequest()

			requestAuthenticator := mockcredentialrequest.NewMockTokenCredentialRequestAuthenticator(ctrl)
			requestAuthenticator.EXPECT().AuthenticateTokenCredentialRequest(gomock.Any(), req.DeepCopy()).
				Return(&user.DefaultInfo{Name: "test-user"}, nil)

			storage := NewREST(requestAuthenticator, successfulIssuer(ctrl, fakeNow), schema.GroupResource{}, auditLogger)

			fakeReqContext := audit.WithAuditContext(context.Background())
			audit.WithAuditID(fakeReqContext, "fake-audit-id")

			validationFunctionWasCalled := false
			var validationFunctionSawTokenValue string

			response, err := storage.Create(
				fakeReqContext,
				req,
				func(ctx context.Context, obj runtime.Object) error {
					credentialRequest, _ := obj.(*loginapi.TokenCredentialRequest)
					validationFunctionWasCalled = true
					validationFunctionSawTokenValue = credentialRequest.Spec.Token
					return nil
				},
				&metav1.CreateOptions{})
			r.NoError(err)
			r.NotEmpty(response)
			r.True(validationFunctionWasCalled)
			r.Empty(validationFunctionSawTokenValue)

			wantAuditLog = []testutil.WantedAuditLog{
				testutil.WantAuditLog("TokenCredentialRequest Token Received", map[string]any{
					"auditID": "fake-audit-id",
					"tokenID": tokenToHash(req.Spec.Token),
				}),
				testutil.WantAuditLog("TokenCredentialRequest Authenticated User", map[string]any{
					"auditID": "fake-audit-id",
					"authenticator": map[string]any{
						"apiGroup": "fake-api-group.com",
						"kind":     "FakeAuthenticatorKind",
						"name":     "fake-authenticator-name",
					},
					"issuedClientCert": map[string]any{
						"notBefore": "2024-09-12T04:20:56Z", // this is fakeNow - 5 minutes in UTC
						"notAfter":  "2024-09-12T04:30:56Z", // this is fakeNow + 5 minutes in UTC
					},
					"personalInfo": map[string]any{
						"username": "test-user",
						"groups":   []any{},
						"extras":   map[string]any{},
					},
				}),
			}
		})

		it("CreateFailsWhenRequestOptionsDryRunIsNotEmpty", func() {
			response, err := NewREST(nil, nil, schema.GroupResource{}, auditLogger).Create(
				genericapirequest.NewContext(),
				validCredentialRequest(),
				rest.ValidateAllObjectFunc,
				&metav1.CreateOptions{
					DryRun: []string{"some dry run flag"},
				})

			requireAPIError(t, response, err, apierrors.IsInvalid,
				`.pinniped.dev "request name" is invalid: dryRun: Unsupported value: ["some dry run flag"]`)
		})

		it("CreateFailsWhenNamespaceIsNotEmpty", func() {
			response, err := NewREST(nil, nil, schema.GroupResource{}, auditLogger).Create(
				genericapirequest.WithNamespace(genericapirequest.NewContext(), "some-ns"),
				validCredentialRequest(),
				rest.ValidateAllObjectFunc,
				&metav1.CreateOptions{})

			requireAPIError(t, response, err, apierrors.IsBadRequest, `namespace is not allowed on TokenCredentialRequest: some-ns`)
		})
	}, spec.Sequential())
}

func callCreate(storage *REST, obj runtime.Object) (runtime.Object, error) {
	fakeReqContext := audit.WithAuditContext(context.Background())
	audit.WithAuditID(fakeReqContext, "fake-audit-id")

	return storage.Create(
		fakeReqContext,
		obj,
		rest.ValidateAllObjectFunc,
		&metav1.CreateOptions{
			DryRun: []string{},
		})
}

func validCredentialRequest() *loginapi.TokenCredentialRequest {
	return validCredentialRequestWithToken("some token")
}

func validCredentialRequestWithToken(token string) *loginapi.TokenCredentialRequest {
	return credentialRequest(loginapi.TokenCredentialRequestSpec{
		Token: token,
		Authenticator: corev1.TypedLocalObjectReference{
			APIGroup: ptr.To("fake-api-group.com"),
			Kind:     "FakeAuthenticatorKind",
			Name:     "fake-authenticator-name",
		},
	})
}

func credentialRequest(spec loginapi.TokenCredentialRequestSpec) *loginapi.TokenCredentialRequest {
	return &loginapi.TokenCredentialRequest{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "request name",
		},
		Spec: spec,
	}
}

func requireAPIError(t *testing.T, response runtime.Object, err error, expectedErrorTypeChecker func(err error) bool, expectedErrorMessage string) {
	t.Helper()
	require.Nil(t, response)
	require.True(t, expectedErrorTypeChecker(err))
	var status apierrors.APIStatus
	errors.As(err, &status)
	require.Contains(t, status.Status().Message, expectedErrorMessage)
}

func requireSuccessfulResponseWithAuthenticationFailureMessage(t *testing.T, err error, response runtime.Object) {
	t.Helper()
	require.NoError(t, err)
	require.Equal(t, response, &loginapi.TokenCredentialRequest{
		Status: loginapi.TokenCredentialRequestStatus{
			Credential: nil,
			Message:    ptr.To("authentication failed"),
		},
	})
}

func successfulIssuer(ctrl *gomock.Controller, fakeNow time.Time) clientcertissuer.ClientCertIssuer {
	clientCertIssuer := mockissuer.NewMockClientCertIssuer(ctrl)
	clientCertIssuer.EXPECT().
		IssueClientCertPEM(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(&cert.PEM{
			CertPEM:   []byte("test-cert"),
			KeyPEM:    []byte("test-key"),
			NotBefore: fakeNow.Add(-5 * time.Minute),
			NotAfter:  fakeNow.Add(5 * time.Minute),
		}, nil)
	return clientCertIssuer
}

func TestValidateExtraKeys(t *testing.T) {
	tests := []struct {
		name    string
		extras  map[string][]string
		wantErr string
	}{
		{
			name: "allowed extras keys cause no error",
			extras: map[string][]string{
				"foo.com/example":                            {"foo"},
				"x.y.z.foo.io/some-path":                     {"bar"},
				"authentication.kubernetes.io/credential-id": {"baz"},
			},
		},
		{
			name: "empty extras keys cause error",
			extras: map[string][]string{
				"":                 {"foo"},
				"foo.io/some-path": {"bar"},
			},
			wantErr: `userInfo extra key "": Required value`,
		},
		{
			name: "extras keys not prefixed by domain name cause error",
			extras: map[string][]string{
				"foo":              {"foo"},
				"foo.io/some-path": {"bar"},
			},
			wantErr: `userInfo extra key "foo": Invalid value: "foo": must be a domain-prefixed path (such as "acme.io/foo")`,
		},
		{
			name: "extras keys with upper case chars cause error",
			extras: map[string][]string{
				"fooBar.com/value": {"foo"},
				"foo.io/some-path": {"bar"},
			},
			wantErr: `userInfo extra key "fooBar.com/value": Invalid value: "fooBar.com": ` +
				`a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', ` +
				`and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is ` +
				`'[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')`,
		},
		{
			name: "extras keys with unexpected chars in domain name cause error",
			extras: map[string][]string{
				"foobar🦭.com/path": {"foo"},
				"foo.io/some-path": {"bar"},
			},
			wantErr: `userInfo extra key "foobar🦭.com/path": Invalid value: "foobar🦭.com": ` +
				`a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', ` +
				`and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is ` +
				`'[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')`,
		},
		{
			name: "extras keys with unexpected chars in path cause error",
			extras: map[string][]string{
				"foobar.com/🦭":     {"foo"},
				"foo.io/some-path": {"bar"},
			},
			wantErr: `userInfo extra key "foobar.com/🦭": Invalid value: "🦭": ` +
				`Invalid path (regex used for validation is '[A-Za-z0-9/\-._~%!$&'()*+,;=:]+')`,
		},
		{
			name: "extras keys with k8s.io cause error",
			extras: map[string][]string{
				"k8s.io/some-path":     {"foo"},
				"sub.k8s.io/some-path": {"foo"},
				"foo.io/some-path":     {"bar"},
			},
			wantErr: `[` +
				`userInfo extra key "k8s.io/some-path": Invalid value: "k8s.io/some-path": k8s.io, kubernetes.io and their subdomains are reserved for Kubernetes use, ` +
				`userInfo extra key "sub.k8s.io/some-path": Invalid value: "sub.k8s.io/some-path": k8s.io, kubernetes.io and their subdomains are reserved for Kubernetes use` +
				`]`,
		},
		{
			name: "extras keys with kubernetes.io cause error",
			extras: map[string][]string{
				"kubernetes.io/some-path":     {"foo"},
				"sub.kubernetes.io/some-path": {"foo"},
				"foo.io/some-path":            {"bar"},
			},
			wantErr: `[` +
				`userInfo extra key "kubernetes.io/some-path": Invalid value: "kubernetes.io/some-path": k8s.io, kubernetes.io and their subdomains are reserved for Kubernetes use, ` +
				`userInfo extra key "sub.kubernetes.io/some-path": Invalid value: "sub.kubernetes.io/some-path": k8s.io, kubernetes.io and their subdomains are reserved for Kubernetes use` +
				`]`,
		},
		{
			name: "extras keys with equals sign cause error",
			extras: map[string][]string{
				"foobar.com/some=path": {"foo"},
				"foo.io/some-path":     {"bar"},
			},
			wantErr: `userInfo extra key "foobar.com/some=path": Invalid value: "foobar.com/some=path": Pinniped does not allow extra key names to contain equals sign`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateExtraKeys(tt.extras)

			if tt.wantErr == "" {
				require.Nilf(t, err, "wanted no error but got %s", err.ToAggregate())
			} else {
				require.EqualError(t, err.ToAggregate(), tt.wantErr)
			}
		})
	}
}
