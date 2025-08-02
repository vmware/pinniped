#!/bin/bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

CLUSTER_NAME="$(cat gke-cluster-pool/name)"
export CLUSTER_NAME
export KUBECONFIG="gke-cluster-pool/metadata"

# Parse the region or zone name from the cluster name, in case it was created in a different region/zone
# compared to the region/zone in which we are currently creating new clusters.
zone=${CLUSTER_NAME##*-zone-}
region=${CLUSTER_NAME##*-region-}

# If the region/zone name was empty, or if there was no region/zone delimiter in the cluster name to start with...
if [[ (-z $zone || "$CLUSTER_NAME" != *"-zone-"*) && (-z $region || "$CLUSTER_NAME" != *"-region-"*) ]]; then
  echo "Umm... the cluster name $CLUSTER_NAME did not contain either region or zone name."
  exit 1
fi

# Decide if we have a regional or zonal cluster.
if [[ -n "$region" ]]; then
  region_or_zone_flag="--region=$region"
else
  region_or_zone_flag="--zone=$zone"
fi

gcloud auth activate-service-account "$GCP_SERVICE_ACCOUNT" --key-file <(echo "$GCP_JSON_KEY") --project "$GCP_PROJECT"

for i in $(seq 1 10); do
  echo "Checking $CLUSTER_NAME for ongoing operations (iteration $i)...."
  running_ops=$(gcloud container operations list \
    --filter="targetLink:$CLUSTER_NAME AND status != done" \
    --project "$GCP_PROJECT" "$region_or_zone_flag" --format yaml)
  if [[ -z "$running_ops" ]]; then
    echo
    break
  fi
  echo "Found a running cluster operation:"
  echo "$running_ops"
  echo
  # Give some time for the operation to finsh before checking again.
  sleep 30
done

echo "Removing $CLUSTER_NAME..."
gcloud container clusters delete "$CLUSTER_NAME" "$region_or_zone_flag" --quiet
