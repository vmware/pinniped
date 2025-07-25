// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package credentialrequest provides REST functionality for the CredentialRequest resource.
package credentialrequest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"

	loginapi "go.pinniped.dev/generated/latest/apis/concierge/login"
	"go.pinniped.dev/internal/auditevent"
	"go.pinniped.dev/internal/clientcertissuer"
	"go.pinniped.dev/internal/plog"
)

// clientCertificateTTL is the TTL for short-lived client certificates returned by this API.
const clientCertificateTTL = 5 * time.Minute

type TokenCredentialRequestAuthenticator interface {
	AuthenticateTokenCredentialRequest(ctx context.Context, req *loginapi.TokenCredentialRequest) (user.Info, error)
}

func NewREST(
	authenticator TokenCredentialRequestAuthenticator,
	issuer clientcertissuer.ClientCertIssuer,
	resource schema.GroupResource,
	auditLogger plog.AuditLogger,
) *REST {
	return &REST{
		authenticator:  authenticator,
		issuer:         issuer,
		tableConvertor: rest.NewDefaultTableConvertor(resource),
		auditLogger:    auditLogger,
	}
}

type REST struct {
	authenticator  TokenCredentialRequestAuthenticator
	issuer         clientcertissuer.ClientCertIssuer
	tableConvertor rest.TableConvertor
	auditLogger    plog.AuditLogger
}

// Assert that our *REST implements all the optional interfaces that we expect it to implement.
var _ interface {
	rest.Creater //nolint:misspell // this name comes from a dependency
	rest.NamespaceScopedStrategy
	rest.Scoper
	rest.Storage
	rest.CategoriesProvider
	rest.SingularNameProvider
	rest.Lister
} = (*REST)(nil)

func (*REST) New() runtime.Object {
	return &loginapi.TokenCredentialRequest{}
}

func (*REST) Destroy() {}

func (*REST) NewList() runtime.Object {
	return &loginapi.TokenCredentialRequestList{}
}

func (*REST) List(_ context.Context, _ *metainternalversion.ListOptions) (runtime.Object, error) {
	return &loginapi.TokenCredentialRequestList{
		ListMeta: metav1.ListMeta{
			ResourceVersion: "0", // this resource version means "from the API server cache"
		},
		Items: []loginapi.TokenCredentialRequest{}, // avoid sending nil items list
	}, nil
}

func (r *REST) ConvertToTable(ctx context.Context, obj runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return r.tableConvertor.ConvertToTable(ctx, obj, tableOptions)
}

func (*REST) NamespaceScoped() bool {
	return false
}

func (*REST) Categories() []string {
	return []string{"pinniped"}
}

func (*REST) GetSingularName() string {
	return "tokencredentialrequest"
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (runtime.Object, error) {
	credentialRequest, err := validateRequest(ctx, obj, createValidation, options)
	if err != nil {
		// Bad requests are not audit logged because the Kubernetes audit log will show the response's status error code.
		plog.DebugErr("TokenCredentialRequest request object validation error", err)
		return nil, err
	}

	// Allow cross-referencing the token with the Supervisor's audit logs.
	r.auditLogger.Audit(auditevent.TokenCredentialRequestTokenReceived, &plog.AuditParams{
		ReqCtx: ctx,
		KeysAndValues: []any{
			"tokenID", fmt.Sprintf("%x", sha256.Sum256([]byte(credentialRequest.Spec.Token))),
		},
	})

	userInfo, err := r.authenticator.AuthenticateTokenCredentialRequest(ctx, credentialRequest)
	if err != nil {
		r.auditLogger.Audit(auditevent.TokenCredentialRequestUnexpectedError, &plog.AuditParams{
			ReqCtx: ctx,
			KeysAndValues: []any{
				"reason", "authenticator returned an error",
				"err", err.Error(),
				"authenticator", credentialRequest.Spec.Authenticator,
			},
		})
		return authenticationFailedResponse(), nil
	}

	if userInfo == nil {
		r.auditLogger.Audit(auditevent.TokenCredentialRequestAuthenticationFailed, &plog.AuditParams{
			ReqCtx: ctx,
			KeysAndValues: []any{
				"reason", "auth rejected by authenticator",
				"authenticator", credentialRequest.Spec.Authenticator,
			},
		})
		return authenticationFailedResponse(), nil
	}

	if err = validateUserInfo(userInfo); err != nil {
		r.auditLogger.Audit(auditevent.TokenCredentialRequestUnsupportedUserInfo, &plog.AuditParams{
			ReqCtx: ctx,
			PIIKeysAndValues: []any{
				"userInfoName", userInfo.GetName(),
				"userInfoUID", userInfo.GetUID(),
			},
			KeysAndValues: []any{
				"userInfoExtrasCount", len(userInfo.GetExtra()),
				"reason", "unsupported value in userInfo returned by authenticator",
				"err", err.Error(),
				"authenticator", credentialRequest.Spec.Authenticator,
			},
		})
		return authenticationFailedResponse(), nil
	}

	pem, err := r.issuer.IssueClientCertPEM(
		userInfo.GetName(),
		userInfo.GetGroups(),
		extrasAsKeyValues(userInfo.GetExtra()),
		clientCertificateTTL,
	)
	if err != nil {
		r.auditLogger.Audit(auditevent.TokenCredentialRequestUnexpectedError, &plog.AuditParams{
			ReqCtx: ctx,
			KeysAndValues: []any{
				"reason", "cert issuer returned an error",
				"err", err.Error(),
				"authenticator", credentialRequest.Spec.Authenticator,
			},
		})
		return authenticationFailedResponse(), nil
	}

	notBefore := metav1.NewTime(pem.NotBefore)
	notAfter := metav1.NewTime(pem.NotAfter)

	r.auditLogger.Audit(auditevent.TokenCredentialRequestAuthenticatedUser, &plog.AuditParams{
		ReqCtx: ctx,
		PIIKeysAndValues: []any{
			"username", userInfo.GetName(),
			"groups", userInfo.GetGroups(),
			"extras", userInfo.GetExtra(),
		},
		KeysAndValues: []any{
			"issuedClientCert", map[string]string{
				"notBefore": notBefore.Format(time.RFC3339),
				"notAfter":  notAfter.Format(time.RFC3339),
			},
			"authenticator", credentialRequest.Spec.Authenticator,
		},
	})

	return &loginapi.TokenCredentialRequest{
		Status: loginapi.TokenCredentialRequestStatus{
			Credential: &loginapi.ClusterCredential{
				ExpirationTimestamp:   notAfter,
				ClientCertificateData: string(pem.CertPEM),
				ClientKeyData:         string(pem.KeyPEM),
			},
		},
	}, nil
}

func extrasAsKeyValues(extras map[string][]string) []string {
	var kvExtras []string
	for k, v := range extras {
		for _, vv := range v {
			// Note that this will result in a key getting repeated if it has multiple values.
			kvExtras = append(kvExtras, fmt.Sprintf("%s=%s", k, vv))
		}
	}
	slices.Sort(kvExtras)
	return kvExtras
}

func validateRequest(ctx context.Context, obj runtime.Object, createValidation rest.ValidateObjectFunc, options *metav1.CreateOptions) (*loginapi.TokenCredentialRequest, error) {
	credentialRequest, ok := obj.(*loginapi.TokenCredentialRequest)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("not a TokenCredentialRequest: %#v", obj))
	}

	if len(credentialRequest.Spec.Token) == 0 {
		errs := field.ErrorList{field.Required(field.NewPath("spec", "token", "value"), "token must be supplied")}
		return nil, apierrors.NewInvalid(loginapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
	}

	// just a sanity check, not sure how to honor a dry run on a virtual API
	if options != nil {
		if len(options.DryRun) != 0 {
			errs := field.ErrorList{field.NotSupported(field.NewPath("dryRun"), options.DryRun, []string(nil))}
			return nil, apierrors.NewInvalid(loginapi.Kind(credentialRequest.Kind), credentialRequest.Name, errs)
		}
	}

	if namespace := genericapirequest.NamespaceValue(ctx); len(namespace) != 0 {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("namespace is not allowed on TokenCredentialRequest: %v", namespace))
	}

	// let dynamic admission webhooks have a chance to validate (but not mutate) as well
	if createValidation != nil {
		requestForValidation := obj.DeepCopyObject()
		requestForValidation.(*loginapi.TokenCredentialRequest).Spec.Token = ""
		if err := createValidation(ctx, requestForValidation); err != nil {
			return nil, err
		}
	}

	return credentialRequest, nil
}

func validateUserInfo(userInfo user.Info) error {
	if len(userInfo.GetName()) == 0 {
		return errors.New("empty username is not allowed")
	}

	// certs cannot assert UID
	if len(userInfo.GetUID()) != 0 {
		return errors.New("UIDs are not supported")
	}

	allErrs := validateExtraKeys(userInfo.GetExtra())
	if allErrs != nil {
		return fmt.Errorf("authenticator returned illegal userInfo extra key(s): %w", allErrs.ToAggregate())
	}

	return nil
}

func validateExtraKeys(extras map[string][]string) field.ErrorList {
	// Prevent WebhookAuthenticators from returning illegal extras.
	//
	// JWTAuthenticators are already effectively prevented from returning illegal extras because we validate
	// the extra key names that are configured on the JWTAuthenticator CRD, but it shouldn't hurt to check again
	// here for JWTAuthenticators too.
	//
	// These validations are inspired by those done in k8s.io/apiserver@v0.33.2/pkg/apis/apiserver/validation/validation.go.
	//
	// Keys must be a domain-prefix path (e.g. example.org/foo).
	// All characters before the first "/" must be a valid subdomain as defined by RFC 1123.
	// All characters trailing the first "/" must be valid HTTP Path characters as defined by RFC 3986.
	// k8s.io, kubernetes.io and their subdomains are reserved for Kubernetes use and cannot be used.
	// Keys must be lowercase.
	var allErrs field.ErrorList

	// Sort the keys for stable order of error messages.
	keys := make([]string, 0, len(extras))
	for k := range extras {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, extraKey := range keys {
		path := field.NewPath(fmt.Sprintf("userInfo extra key %q", extraKey))

		// This is a special key that is always added by authenticators starting in K8s 1.32, so always allow it.
		if extraKey == "authentication.kubernetes.io/credential-id" {
			continue
		}

		// Noe that IsDomainPrefixedPath also checks for empty keys.
		allErrs = append(allErrs, utilvalidation.IsDomainPrefixedPath(path, extraKey)...)

		// Cannot use reserved prefixes.
		if isKubernetesDomainPrefix(extraKey) {
			allErrs = append(allErrs, field.Invalid(path, extraKey, "k8s.io, kubernetes.io and their subdomains are reserved for Kubernetes use"))
		}

		// We can't allow equals signs in the key name, because we need to be able to encode the key names and values
		// into the client cert as OU "keyName=value".
		if strings.Contains(extraKey, "=") {
			allErrs = append(allErrs, field.Invalid(path, extraKey, "Pinniped does not allow extra key names to contain equals sign"))
		}
	}

	return allErrs
}

func isKubernetesDomainPrefix(key string) bool {
	domainPrefix := getDomainPrefix(key)
	if domainPrefix == "kubernetes.io" || strings.HasSuffix(domainPrefix, ".kubernetes.io") {
		return true
	}
	if domainPrefix == "k8s.io" || strings.HasSuffix(domainPrefix, ".k8s.io") {
		return true
	}
	return false
}

func getDomainPrefix(key string) string {
	if parts := strings.SplitN(key, "/", 2); len(parts) == 2 {
		return parts[0]
	}
	return ""
}

func authenticationFailedResponse() *loginapi.TokenCredentialRequest {
	m := "authentication failed"
	return &loginapi.TokenCredentialRequest{
		Status: loginapi.TokenCredentialRequestStatus{
			Credential: nil,
			Message:    &m,
		},
	}
}
