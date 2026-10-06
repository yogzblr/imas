locals {
  resource_group = "imas-uat-${var.run_id}"

  # Time of the first apply, kept in state (see terraform_data.created_at), so
  # expires_at does not move on later plans. Re-applying with a larger
  # keep_hours pushes it out from the same start.
  expires_at = timeadd(terraform_data.created_at.output, "${var.run_budget_hours + var.keep_hours}h")

  # Shared contract: every resource tagged purpose=imas-uat, run_id and
  # expires_at (RFC 3339, UTC). release_tag is extra, for people reading the
  # portal.
  tags = {
    purpose     = "imas-uat"
    run_id      = var.run_id
    expires_at  = local.expires_at
    release_tag = var.release_tag
  }

  cidr = {
    vnet    = "10.60.0.0/16"
    dmz     = "10.60.1.0/24"
    core    = "10.60.2.0/24"
    tenants = "10.60.3.0/24"
    bastion = "10.60.4.0/26"
  }

  hubs = {
    dmz = {
      name      = "uat-dmz"
      size      = var.dmz_size
      disk_gb   = var.dmz_os_disk_gb
      dns_label = "uat${var.run_id}-dmz"
    }
    core = {
      name      = "uat-core"
      size      = var.core_size
      disk_gb   = var.core_os_disk_gb
      dns_label = "uat${var.run_id}-core"
    }
  }

  # Both tenants get one sprout of each OS. The VM name is the key everywhere
  # (Shared contract: sprouts is a map keyed by VM name).
  linux_sprouts = {
    "t1-ubuntu" = { tenant = 1, os = "ubuntu" }
    "t1-alma"   = { tenant = 1, os = "alma" }
    "t2-ubuntu" = { tenant = 2, os = "ubuntu" }
    "t2-alma"   = { tenant = 2, os = "alma" }
  }
  windows_sprouts = {
    "t1-win" = { tenant = 1, os = "windows" }
    "t2-win" = { tenant = 2, os = "windows" }
  }
  sprouts = merge(local.linux_sprouts, local.windows_sprouts)

  images = {
    ubuntu  = split(":", var.ubuntu_image)
    alma    = split(":", var.alma_image)
    windows = split(":", var.windows_image)
  }
}

# Frozen at the first apply: plantimestamp() is known at plan time, and
# ignore_changes keeps the stored value on every later plan.
resource "terraform_data" "created_at" {
  input = plantimestamp()

  lifecycle {
    ignore_changes = [input]
  }
}

resource "azurerm_resource_group" "run" {
  name     = local.resource_group
  location = var.region
  tags     = local.tags
}

# Per-run credentials. They live only in this run's state blob and in the
# sensitive outputs; nothing is written to disk or committed.

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "random_password" "windows_admin" {
  length           = 24
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
  override_special = "!#%*-_=+?"
}

# Network: one VNet, three workload subnets and AzureBastionSubnet.

resource "azurerm_virtual_network" "uat" {
  name                = "uat-vnet"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  address_space       = [local.cidr.vnet]
  tags                = local.tags
}

resource "azurerm_subnet" "workload" {
  for_each = {
    dmz     = local.cidr.dmz
    core    = local.cidr.core
    tenants = local.cidr.tenants
  }

  name                 = each.key
  resource_group_name  = azurerm_resource_group.run.name
  virtual_network_name = azurerm_virtual_network.uat.name
  address_prefixes     = [each.value]

  # Every VM has its own Standard public IP for outbound traffic; Azure's
  # implicit default outbound access is not used.
  default_outbound_access_enabled = false
}

resource "azurerm_subnet" "bastion" {
  # The name is fixed by Azure.
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.run.name
  virtual_network_name = azurerm_virtual_network.uat.name
  address_prefixes     = [local.cidr.bastion]
}
