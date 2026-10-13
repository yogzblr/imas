# The HA run's object store (P24, brief H-azure-next-runs.md H4; design
# D18): Azure Blob behind the farmer chart's Versity Gateway
# (versity.enabled). Created only when the core hub has more than one node;
# the single-node run keeps RustFS on the core hub and gets no account.
#
# The account only: the containers (imas-recipes, imas-jobs,
# imas-sprout-jwts, imas-accounts) are the buckets the chart's
# createBuckets Job makes through the gateway, which keeps each bucket's
# owner and policy on the container it creates. A container made here would
# be a bucket the gateway's root does not own, and the Job would fail on it.
#
# The gateway signs in with the account key (versity.azure.credentialsSecret,
# which uat/hub/core/install.sh makes from the sensitive output below). The
# account is the run's own: tagged like every resource of the run, in the
# run's resource group, gone with it (destroy.sh's teardown check lists
# everything tagged run_id). HTTPS only, TLS 1.2, no anonymous blob access.
# Its name is fixed per run: imasuat<run_id> (17 characters at most, lower
# case letters and digits, as Azure requires).
locals {
  object_store_enabled = var.core_node_count > 1
}

resource "azurerm_storage_account" "object_store" {
  count = local.object_store_enabled ? 1 : 0

  name                = "imasuat${var.run_id}"
  resource_group_name = azurerm_resource_group.run.name
  location            = azurerm_resource_group.run.location
  account_kind        = "StorageV2"
  account_tier        = "Standard"
  # Zone-redundant where the region has zones (the nodes are spread over
  # them too), locally redundant where it has none.
  account_replication_type        = length(local.zones) > 0 ? "ZRS" : "LRS"
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  # The gateway authenticates with the account key (versitygw azure).
  shared_access_key_enabled = true
  tags                      = local.tags
}
