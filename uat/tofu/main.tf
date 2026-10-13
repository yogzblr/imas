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

  # private_ports are what other subnets reach on the hub's private address
  # (sprouts and core to the DMZ, the DMZ to core); public_ports what the
  # runner reaches on its public address (network-security.tf). A hub of
  # several nodes carries both on load balancers (lb.tf), with the k0s API.
  hubs = {
    dmz = {
      name          = "uat-dmz"
      count         = var.dmz_node_count
      size          = var.dmz_node_size
      disk_gb       = var.dmz_os_disk_gb
      dns_label     = "uat${var.run_id}-dmz"
      private_ports = [var.envoy_port, var.bus_port]
      public_ports  = [var.envoy_port]
    }
    core = {
      name          = "uat-core"
      count         = var.core_node_count
      size          = var.core_node_size
      disk_gb       = var.core_os_disk_gb
      dns_label     = "uat${var.run_id}-core"
      private_ports = [var.farmer_api_port, var.accounts_store_port]
      public_ports  = [var.core_public_port]
    }
  }

  # The hubs with more than one node: the HA topology.
  ha_hubs = { for k, h in local.hubs : k => h if h.count > 1 }

  # The k0s API on every hub node (k0s's default), behind the internal load
  # balancer of an HA hub.
  kube_api_port = 6443

  # The region's availability zones, from the provider (empty where the
  # region has none). The nodes of an HA hub go round them; a single node
  # gets no zone, as before.
  zones = sort(distinct([for z in data.azurerm_location.run.zone_mappings : z.logical_zone]))

  # One entry per hub VM, keyed by VM name: uat-dmz and uat-core for a hub of
  # one node (unchanged), uat-<hub>-1 to uat-<hub>-N for an HA hub. The
  # single node keeps the hub's public DNS label; on an HA hub it moves to the
  # public load balancer.
  hub_nodes = merge([
    for k, h in local.hubs : {
      for i in range(h.count) : (h.count == 1 ? h.name : "${h.name}-${i + 1}") => {
        hub       = k
        index     = i
        size      = h.size
        disk_gb   = h.disk_gb
        zone      = h.count > 1 && length(local.zones) > 0 ? local.zones[i % length(local.zones)] : null
        dns_label = h.count == 1 ? h.dns_label : null
      }
    }
  ]...)

  # Node names per hub, in index order.
  hub_node_names = {
    for k, h in local.hubs : k => [for i in range(h.count) : (h.count == 1 ? h.name : "${h.name}-${i + 1}")]
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

# Zones of the region (logical zone names, "1" to "3"); an empty list where
# the region has none.
data "azurerm_location" "run" {
  location = var.region
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

  # Every VM has its own Standard public IP for outbound traffic (the nodes
  # of an HA hub too: the load balancers' rules disable outbound SNAT);
  # Azure's implicit default outbound access is not used.
  default_outbound_access_enabled = false
}

resource "azurerm_subnet" "bastion" {
  # The name is fixed by Azure.
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.run.name
  virtual_network_name = azurerm_virtual_network.uat.name
  address_prefixes     = [local.cidr.bastion]
}
