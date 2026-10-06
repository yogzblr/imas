# UAT.1: the Azure side of the UAT gate (docs/claude-code-parallel-build-plan.md, section 4h).
#
# Providers: azurerm (MPL-2.0), random and tls (MPL-2.0) only. terraform_data is
# built into OpenTofu and is not a provider.
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
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # State lives in the storage account the bootstrap stack creates, one blob per
  # run (key imas-uat/<run_id>.tfstate), so a keep_hours run can be destroyed by a
  # later job. Partial configuration: resource_group_name, storage_account_name,
  # container_name and key are given at init with -backend-config (see README.md
  # and destroy.sh). Entra ID auth only: the bootstrap disables shared keys.
  backend "azurerm" {
    use_azuread_auth = true
  }
}

# Subscription, tenant and client come from the environment (ARM_SUBSCRIPTION_ID,
# ARM_TENANT_ID, ARM_CLIENT_ID and ARM_USE_OIDC=true in the workflow, or an az
# login by hand). Nothing is hard coded here.
provider "azurerm" {
  # The owner registers the resource providers once (section 4h prerequisites).
  resource_provider_registrations = "none"

  features {
    resource_group {
      # The run's group is created for the run and holds nothing else, so
      # destroy removes it even if Azure added something tofu does not track.
      prevent_deletion_if_contains_resources = false
    }
    virtual_machine {
      # OS disks go with their VM; NICs and public IPs are tofu resources and
      # are destroyed with it. Together this is the "delete option" for every
      # disk, NIC and public IP (see README.md, "Destroy semantics").
      delete_os_disk_on_deletion     = true
      skip_shutdown_and_force_delete = true
    }
  }
}
