// Copyright 2024-2026 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package admissionpluginconfig

import (
	"errors"
	"fmt"
	"slices"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	mutatingadmissionpolicy "k8s.io/apiserver/pkg/admission/plugin/policy/mutating"
	validatingadmissionpolicy "k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/discovery"

	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
)

// ValidateAdmissionPluginNames returns an error if any of the given pluginNames is unrecognized.
func ValidateAdmissionPluginNames(pluginNames []string) error {
	var pluginsNotFound []string
	admissionOptions := options.NewAdmissionOptions()
	for _, pluginName := range pluginNames {
		if !slices.Contains(admissionOptions.RecommendedPluginOrder, pluginName) {
			pluginsNotFound = append(pluginsNotFound, pluginName)
		}
	}
	if len(pluginsNotFound) > 0 {
		return fmt.Errorf("admission plugin names not recognized: %s (each must be one of %s)",
			pluginsNotFound, admissionOptions.RecommendedPluginOrder)
	}
	return nil
}

// ConfigureAdmissionPlugins may choose to reconfigure the admission plugins present on the given
// RecommendedOptions by mutating it.
//
// The ValidatingAdmissionPolicy feature gate became enabled by default in Kube 1.30.
// When Pinniped is compiled using the Kube 1.30+ libraries, and when installed onto a Kube cluster older than 1.30,
// then the new admission ValidatingAdmissionPolicy plugin prevents all our aggregated APIs from working, seemingly
// because it fails to sync informers created for watching the related resources. As a workaround, ask the k8s API
// server if it has the ValidatingAdmissionPolicy resource, and configure our admission plugins accordingly.
//
// Any plugin name passed via the disableAdmissionPlugins parameter will also be disabled.
// The values in this parameter should be validated by the caller using ValidateAdmissionPluginNames before
// being passed into this function.
func ConfigureAdmissionPlugins(recommendedOptions *options.RecommendedOptions, disableAdmissionPlugins []string) error {
	k8sClient, err := kubeclient.New()
	if err != nil {
		return fmt.Errorf("failed to create kube client: %w", err)
	}
	return configureAdmissionPlugins(k8sClient.Kubernetes.Discovery(), recommendedOptions, disableAdmissionPlugins)
}

// configureAdmissionPlugins is the same as ConfigureAdmissionPlugins but allows client injection for unit testing.
func configureAdmissionPlugins(
	discoveryClient discovery.ServerResourcesInterface,
	recommendedOptions *options.RecommendedOptions,
	disableAdmissionPlugins []string,
) error {
	if !slices.Contains(disableAdmissionPlugins, validatingadmissionpolicy.PluginName) || !slices.Contains(disableAdmissionPlugins, mutatingadmissionpolicy.PluginName) {
		discoveredResources, err := performAPIDiscovery(discoveryClient)
		if err != nil {
			return fmt.Errorf("failed to perform k8s API discovery for purpose of checking availability of %s resource types: %w",
				admissionregistrationv1.GroupName, err)
		}

		disableAdmissionPlugins = autoDisablePluginWhenResourceNotFound(
			disableAdmissionPlugins, discoveredResources, validatingadmissionpolicy.PluginName, "1.30",
		)

		disableAdmissionPlugins = autoDisablePluginWhenResourceNotFound(
			disableAdmissionPlugins, discoveredResources, mutatingadmissionpolicy.PluginName, "1.36",
		)
	}

	// Mutate the recommendedOptions to potentially disable some admission plugins.
	if len(disableAdmissionPlugins) > 0 {
		recommendedOptions.Admission.DisablePlugins = disableAdmissionPlugins
	}
	return nil
}

func autoDisablePluginWhenResourceNotFound(disableAdmissionPlugins []string, resources []*metav1.APIResourceList, pluginName string, since string) []string {
	if !slices.Contains(disableAdmissionPlugins, pluginName) {
		// The admin did not explicitly disable the plugin, but we may still need to disable it if
		// the Kubernetes cluster on which we are running is too old. Check if the API server has such a resource.
		hasResource := k8sAPIServerHasResource(resources, pluginName)

		if !hasResource {
			plog.Warning("could not find resource type on this Kubernetes cluster "+
				"(which is normal for older Kubernetes clusters); "+
				"disabling admission plugins for all Pinniped aggregated API resource types for that Kind",
				"kind", pluginName, "kindIntroducedInKubernetesVersion", since)

			// Customize the admission plugins to avoid using the new plugin.
			disableAdmissionPlugins = append(disableAdmissionPlugins, pluginName)
		}
	}

	return disableAdmissionPlugins
}

func performAPIDiscovery(discoveryClient discovery.ServerResourcesInterface) ([]*metav1.APIResourceList, error) {
	// Perform discovery. We are looking for resources in group admissionregistration.k8s.io at any version.
	resources, err := discoveryClient.ServerPreferredResources()

	partialErr := &discovery.ErrGroupDiscoveryFailed{}
	if resources != nil && errors.As(err, &partialErr) {
		// This is a partial discovery error, most likely caused by Pinniped's own aggregated APIs
		// not being ready yet since this Pinniped pod is typically in the process of starting up
		// when this code is reached. Check if the group that we care about is in the error's list
		// of failed API groups.
		for groupVersion := range partialErr.Groups {
			if groupVersion.Group == admissionregistrationv1.GroupName {
				// There was an error for the specific group that we are trying to find, so
				// return an error. If we don't arrive here, then it must have been error(s) for
				// some other group(s) that we are not looking for, so we can ignore those error(s).
				return nil, err
			}
		}
	} else if err != nil {
		// We got some other type of error aside from a partial failure.
		return nil, err
	}

	return resources, nil
}

func k8sAPIServerHasResource(resources []*metav1.APIResourceList, resourceKind string) bool {
	// Now look at all discovered groups until we find version v1 of group admissionregistration.k8s.io.
	for _, resourcesPerGV := range resources {
		if resourcesPerGV.GroupVersion == admissionregistrationv1.SchemeGroupVersion.String() {
			// Found the group, so now look to see if it includes the given resourceKind as a resource type,
			// which went GA in Kubernetes 1.30, and could be enabled by a feature flag in previous versions.
			for _, resource := range resourcesPerGV.APIResources {
				if resource.Kind == resourceKind {
					// Found it!
					plog.Info("found "+admissionregistrationv1.GroupName+" resource on this Kubernetes cluster",
						"groupVersion", resourcesPerGV.GroupVersion, "kind", resource.Kind)
					return true
				}
			}
		}
	}

	// Didn't the resource kind on this cluster.
	return false
}
