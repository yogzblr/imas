# UAT.1 bootstrap: the only UAT pieces that stay up between runs. The owner
# applies this once, by hand, as the subscription Owner (README.md, "Bootstrap,
# once"). It does not create the GitHub OIDC application: that is an owner
# prerequisite in section 4h of docs/claude-code-parallel-build-plan.md.
#
# Its own state is local (it creates the backend the main stack uses). The
# state holds no credential the storage account accepts: shared keys are off.
terraform {
  required_version = ">= 1.8.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.40"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Subscription and tenant come from the environment (ARM_SUBSCRIPTION_ID or the
# az login); nothing is hard coded.
provider "azurerm" {
  resource_provider_registrations = "none"
  # Shared keys are disabled on the state account, so data plane calls use
  # Entra ID.
  storage_use_azuread = true

  features {}
}

data "azurerm_subscription" "current" {}

data "azurerm_client_config" "current" {}

locals {
  # Deliberately NOT purpose=imas-uat: the janitor deletes expired groups
  # with that tag, and this group must never match it.
  tags = {
    purpose = "imas-uat-state"
  }

  storage_account_name = var.storage_account_name != "" ? var.storage_account_name : "imasuatstate${random_string.storage_suffix.result}"

  blob_writers = toset(concat(
    var.state_blob_contributors,
    var.grant_current_principal ? [data.azurerm_client_config.current.object_id] : [],
  ))
}

resource "azurerm_resource_group" "state" {
  name     = var.resource_group_name
  location = var.region
  tags     = local.tags
}

resource "random_string" "storage_suffix" {
  length  = 8
  upper   = false
  special = false
}

resource "azurerm_storage_account" "state" {
  name                     = local.storage_account_name
  resource_group_name      = azurerm_resource_group.state.name
  location                 = azurerm_resource_group.state.location
  account_kind             = "StorageV2"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.tags

  min_tls_version                   = "TLS1_2"
  https_traffic_only_enabled        = true
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  default_to_oauth_authentication   = true
  cross_tenant_replication_enabled  = false
  local_user_enabled                = false
  infrastructure_encryption_enabled = true
  # GitHub-hosted runners have no fixed address, so the endpoint stays public;
  # Entra ID auth and the role assignments below are the gate.
  public_network_access_enabled = true

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 7
    }

    container_delete_retention_policy {
      days = 7
    }
  }
}

resource "azurerm_storage_container" "state" {
  name                  = var.container_name
  storage_account_id    = azurerm_storage_account.state.id
  container_access_type = "private"
}

# Run state holds the run's SSH key and Windows password (as sensitive
# values). The VMs are gone after a run, but the blobs are not kept forever.
resource "azurerm_storage_management_policy" "state" {
  storage_account_id = azurerm_storage_account.state.id

  rule {
    name    = "expire-run-state"
    enabled = true

    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["${var.container_name}/imas-uat/"]
    }

    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = var.state_retention_days
      }
      version {
        delete_after_days_since_creation = 7
      }
    }
  }
}

# Contributor (the GitHub identity's role) has no blob data access, and shared
# keys are off, so whoever reads or writes run state needs this role.
resource "azurerm_role_assignment" "state_blob" {
  for_each = local.blob_writers

  scope                = azurerm_storage_account.state.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = each.value
}

# A Contributor (the workflow) cannot remove a lock, so a bug in a teardown or
# janitor job cannot delete the state. Destroy removes the lock first.
resource "azurerm_management_lock" "state" {
  count = var.lock_state_group ? 1 : 0

  name       = "imas-uat-state-do-not-delete"
  scope      = azurerm_resource_group.state.id
  lock_level = "CanNotDelete"
  notes      = "Holds the OpenTofu state of UAT runs (uat/tofu/bootstrap)."

  depends_on = [
    azurerm_storage_account.state,
    azurerm_storage_container.state,
    azurerm_storage_management_policy.state,
    azurerm_role_assignment.state_blob,
  ]
}

# Email alerts on the whole subscription (keep it for UAT only, section 4h).
# A budget alerts; it does not stop anything. The janitor does the cleaning.
resource "azurerm_consumption_budget_subscription" "uat" {
  name            = "imas-uat-monthly"
  subscription_id = data.azurerm_subscription.current.id
  amount          = var.monthly_budget
  time_grain      = "Monthly"

  time_period {
    # The first day of the month of the first apply. Azure wants the first
    # of a month, not earlier than the current one.
    start_date = formatdate("YYYY-MM-01'T'00:00:00'Z'", plantimestamp())
  }

  notification {
    enabled        = true
    operator       = "GreaterThan"
    threshold      = 50
    threshold_type = "Actual"
    contact_emails = [var.budget_email]
  }

  notification {
    enabled        = true
    operator       = "GreaterThan"
    threshold      = 90
    threshold_type = "Actual"
    contact_emails = [var.budget_email]
  }

  notification {
    enabled        = true
    operator       = "GreaterThan"
    threshold      = 100
    threshold_type = "Forecasted"
    contact_emails = [var.budget_email]
  }

  lifecycle {
    ignore_changes = [time_period]
  }
}
