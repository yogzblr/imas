# tofu test for the main stack with mocked providers: nothing reaches Azure.
# Run from uat/tofu: tofu init -backend=false && tofu test

# The provider validates resource ids, so every referenced type gets a
# well-formed mock id (all instances of a type share it; that is fine here).
mock_provider "azurerm" {
  mock_resource "azurerm_resource_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123"
    }
  }
  mock_resource "azurerm_virtual_network" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/virtualNetworks/uat-vnet"
    }
  }
  mock_resource "azurerm_subnet" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/virtualNetworks/uat-vnet/subnets/mock"
    }
  }
  mock_resource "azurerm_network_security_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/networkSecurityGroups/mock"
    }
  }
  mock_resource "azurerm_public_ip" {
    defaults = {
      id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/publicIPAddresses/mock"
      ip_address = "198.51.100.10"
      fqdn       = "mocked.centralindia.cloudapp.azure.com"
    }
  }
  mock_resource "azurerm_network_interface" {
    defaults = {
      id                 = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/networkInterfaces/mock"
      private_ip_address = "10.60.9.9"
    }
  }
  mock_resource "azurerm_linux_virtual_machine" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Compute/virtualMachines/mock"
    }
  }
  mock_resource "azurerm_windows_virtual_machine" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Compute/virtualMachines/mockwin"
    }
  }
  mock_resource "azurerm_lb" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/loadBalancers/mock"
    }
  }
  mock_resource "azurerm_lb_backend_address_pool" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/loadBalancers/mock/backendAddressPools/mock"
    }
  }
  mock_resource "azurerm_lb_probe" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/loadBalancers/mock/probes/mock"
    }
  }
  mock_resource "azurerm_lb_rule" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/loadBalancers/mock/loadBalancingRules/mock"
    }
  }
  # centralindia has three zones.
  mock_data "azurerm_location" {
    defaults = {
      zone_mappings = [
        { logical_zone = "1", physical_zone = "centralindia-az1" },
        { logical_zone = "2", physical_zone = "centralindia-az2" },
        { logical_zone = "3", physical_zone = "centralindia-az3" },
      ]
    }
  }
  mock_resource "azurerm_bastion_host" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/bastionHosts/uat-bastion"
    }
  }
}

mock_provider "random" {}

# A public key only (its private half was thrown away when the test was
# written): the provider checks that the key is a complete SSH2 public key.
mock_provider "tls" {
  mock_resource "tls_private_key" {
    defaults = {
      public_key_openssh = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrgINDMMhc2SXTzPtH3fluuDwf8yam2G3kgi+aUXAyvUNgXW8A+4saNJEjTS5Jt1gLHbsAqvTY60GT2Xsl2uZKATGgN1kC8qrEvXCkYs9lhGvxJOPbZfCCBmo7CG4rAoK8CG2DCPjP4X2QGjZTNhj8wONLDG0K5IUlVq3yCAQsaV4kAj03lSCuG8DjDFPSVAAeasV/7ueIha7w/zt2Joq8G5zdIoINM/DwEALdYgz0sTrZphjymcSR7hiq396xDAUCyZxAelASZFyEkpo8a5aa7+9Wes1d82FA8pwUWHXYgd3YN/IK4HeizFGPEfkXYFNXg2AFU1pzYfEccgwN1lZH"
    }
  }
}

override_resource {
  target = azurerm_subnet.bastion
  values = {
    id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/imas-uat-abc123/providers/Microsoft.Network/virtualNetworks/uat-vnet/subnets/AzureBastionSubnet"
  }
}

variables {
  run_id      = "abc123"
  release_tag = "v0.1.0-rc.4"
  runner_cidr = "203.0.113.7/32"
}

run "names_tags_and_layout" {
  command = apply

  assert {
    condition     = azurerm_resource_group.run.name == "imas-uat-abc123"
    error_message = "resource group must be imas-uat-<run_id>"
  }

  assert {
    condition = (
      azurerm_resource_group.run.tags["purpose"] == "imas-uat" &&
      azurerm_resource_group.run.tags["run_id"] == "abc123" &&
      can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", azurerm_resource_group.run.tags["expires_at"]))
    )
    error_message = "resource group tags must carry purpose, run_id and an RFC 3339 UTC expires_at"
  }

  assert {
    condition     = azurerm_resource_group.run.location == "centralindia"
    error_message = "default region must be centralindia"
  }

  assert {
    condition = (
      azurerm_public_ip.hub["uat-dmz"].domain_name_label == "uatabc123-dmz" &&
      azurerm_public_ip.hub["uat-core"].domain_name_label == "uatabc123-core"
    )
    error_message = "hub DNS labels must be uat<run_id>-dmz and uat<run_id>-core"
  }

  assert {
    condition     = alltrue([for p in concat(values(azurerm_public_ip.hub), values(azurerm_public_ip.sprout), [azurerm_public_ip.bastion]) : p.sku == "Standard" && p.allocation_method == "Static"])
    error_message = "every public IP must be Standard and static"
  }

  assert {
    condition     = alltrue([for p in values(azurerm_public_ip.sprout) : p.domain_name_label == null])
    error_message = "sprout public IPs are outbound only and carry no DNS label"
  }

  assert {
    condition = (
      azurerm_subnet.workload["dmz"].address_prefixes[0] == "10.60.1.0/24" &&
      azurerm_subnet.workload["core"].address_prefixes[0] == "10.60.2.0/24" &&
      azurerm_subnet.workload["tenants"].address_prefixes[0] == "10.60.3.0/24" &&
      azurerm_subnet.bastion.name == "AzureBastionSubnet" &&
      azurerm_subnet.bastion.address_prefixes[0] == "10.60.4.0/26" &&
      contains(azurerm_virtual_network.uat.address_space, "10.60.0.0/16")
    )
    error_message = "VNet and subnet ranges must match the Shared contract"
  }

  assert {
    condition = (
      azurerm_bastion_host.uat.sku == "Standard" &&
      azurerm_bastion_host.uat.tunneling_enabled == true &&
      azurerm_bastion_host.uat.shareable_link_enabled == false &&
      azurerm_bastion_host.uat.ip_connect_enabled == false
    )
    error_message = "Bastion must be Standard with native client tunnelling on, and no IP-based connection in the single-node run"
  }

  assert {
    condition = (
      azurerm_linux_virtual_machine.hub["uat-dmz"].size == "Standard_D2s_v5" &&
      azurerm_linux_virtual_machine.hub["uat-core"].size == "Standard_D8s_v5" &&
      azurerm_linux_virtual_machine.hub["uat-dmz"].os_disk[0].disk_size_gb == 64 &&
      azurerm_linux_virtual_machine.hub["uat-core"].os_disk[0].disk_size_gb == 128 &&
      azurerm_linux_virtual_machine.hub["uat-core"].os_disk[0].storage_account_type == "StandardSSD_LRS"
    )
    error_message = "hub sizes and disks must match the brief"
  }

  assert {
    condition = (
      length(azurerm_linux_virtual_machine.sprout) == 4 &&
      length(azurerm_windows_virtual_machine.sprout) == 2 &&
      alltrue([for v in values(azurerm_linux_virtual_machine.sprout) : v.size == "Standard_B2ls_v2" && v.disable_password_authentication]) &&
      alltrue([for v in values(azurerm_windows_virtual_machine.sprout) : v.size == "Standard_B2ls_v2"])
    )
    error_message = "six sprouts: four Linux B2ls_v2 with key-only SSH, two Windows B2ls_v2"
  }

  assert {
    condition = (
      length(azurerm_linux_virtual_machine.sprout["t1-alma"].plan) == 0 &&
      length(azurerm_linux_virtual_machine.sprout["t2-alma"].plan) == 0 &&
      length(azurerm_linux_virtual_machine.sprout["t1-ubuntu"].plan) == 0
    )
    error_message = "no sprout carries a marketplace plan by default (Azure refuses one for the AlmaLinux image)"
  }

  assert {
    condition     = azurerm_windows_virtual_machine.sprout["t2-win"].source_image_reference[0].sku == "2022-datacenter-core-smalldisk-g2"
    error_message = "Windows sprouts use the Server 2022 Core smalldisk image"
  }

  assert {
    condition     = length(azurerm_virtual_machine_extension.winrm_https) == 2
    error_message = "both Windows sprouts get the WinRM over HTTPS extension"
  }

  assert {
    condition = (
      azurerm_private_dns_zone.uat.name == "uat.imas.internal" &&
      azurerm_private_dns_zone_virtual_network_link.uat.registration_enabled == false &&
      azurerm_private_dns_a_record.hub["dmz"].name == "dmz" &&
      azurerm_private_dns_a_record.hub["core"].name == "core" &&
      toset(azurerm_private_dns_a_record.hub["dmz"].records) == toset(["10.60.9.9"])
    )
    error_message = "dmz.<zone> and core.<zone> must resolve to the hubs' private addresses inside the VNet"
  }

  # One node per hub by default: the single-node run, unchanged. No load
  # balancer, no zone, the hub's DNS label on the node's own public IP.
  assert {
    condition = (
      toset(keys(azurerm_linux_virtual_machine.hub)) == toset(["uat-dmz", "uat-core"]) &&
      alltrue([for v in values(azurerm_linux_virtual_machine.hub) : v.zone == null]) &&
      length(azurerm_lb.internal) == 0 && length(azurerm_lb.public) == 0 && length(azurerm_public_ip.hub_lb) == 0 &&
      length(azurerm_lb_rule.hub) == 0 && length(azurerm_network_interface_backend_address_pool_association.hub) == 0
    )
    error_message = "the default is one VM per hub, uat-dmz and uat-core, with no zone and no load balancer"
  }

  assert {
    condition = (
      tolist(output.uat.dmz.node_names) == tolist(["uat-dmz"]) &&
      tolist(output.uat.core.node_names) == tolist(["uat-core"]) &&
      tolist(output.uat.dmz.node_private_ips) == tolist(["10.60.9.9"]) &&
      output.uat.dmz.api_address == "10.60.9.9" &&
      output.uat.core.api_fqdn == "core-api.uat.imas.internal" &&
      output.uat.dmz.public_ip == "198.51.100.10" &&
      output.uat.dmz.fqdn == "mocked.centralindia.cloudapp.azure.com" &&
      length(output.ha_node_names.core) == 0 && length(output.ha_node_names.dmz) == 0
    )
    error_message = "single node: the API address is the node's own, and no VM is an HA test target"
  }

  assert {
    condition = (
      toset(keys(azurerm_private_dns_a_record.hub_node)) == toset(["uat-dmz", "uat-core"]) &&
      azurerm_private_dns_a_record.hub_api["dmz"].name == "dmz-api" &&
      toset(azurerm_private_dns_a_record.hub_api["core"].records) == toset(["10.60.9.9"])
    )
    error_message = "private DNS has <hub>-api and one record per node"
  }

  # The uat output: exactly the Shared contract's keys.
  assert {
    condition     = toset(keys(output.uat)) == toset(["run_id", "region", "resource_group", "dmz", "core", "sprouts", "bastion", "subnets"])
    error_message = "uat must have exactly the Shared contract's top-level keys"
  }
  assert {
    condition = (
      output.uat.run_id == "abc123" &&
      output.uat.resource_group == "imas-uat-abc123" &&
      output.uat.dmz.name == "uat-dmz" &&
      output.uat.core.name == "uat-core" &&
      output.uat.core.admin_user == "imasuat" &&
      output.uat.bastion.name == "uat-bastion" &&
      toset(keys(output.uat.sprouts)) == toset(["t1-ubuntu", "t1-alma", "t1-win", "t2-ubuntu", "t2-alma", "t2-win"])
    )
    error_message = "uat output must follow the Shared contract"
  }

  assert {
    condition = (
      output.uat.sprouts["t1-win"].connection == "winrm" &&
      output.uat.sprouts["t1-win"].os == "windows" &&
      output.uat.sprouts["t2-alma"].connection == "ssh" &&
      output.uat.sprouts["t2-alma"].tenant == 2 &&
      output.uat.sprouts["t1-ubuntu"].tenant == 1
    )
    error_message = "sprouts carry tenant, os and connection"
  }

  assert {
    condition = alltrue([for k in ["ssh_private_key", "windows_admin_password", "password", "private_key"] :
      !strcontains(jsonencode(output.uat), k)
    ])
    error_message = "the uat output must carry no credential"
  }
}

# uat/access/testdata/uat.json is the sample the access scripts (and other
# briefs) test against; it must keep the shape of the real output.
run "sample_uat_json_matches_output" {
  command = apply

  assert {
    condition = (
      toset(keys(output.uat)) == toset(keys(jsondecode(file("../access/testdata/uat.json")))) &&
      toset(keys(output.uat.dmz)) == toset(keys(jsondecode(file("../access/testdata/uat.json")).dmz)) &&
      toset(keys(output.uat.core)) == toset(keys(jsondecode(file("../access/testdata/uat.json")).core)) &&
      toset(keys(output.uat.sprouts)) == toset(keys(jsondecode(file("../access/testdata/uat.json")).sprouts)) &&
      toset(keys(output.uat.sprouts["t1-win"])) == toset(keys(jsondecode(file("../access/testdata/uat.json")).sprouts["t1-win"])) &&
      toset(keys(output.uat.bastion)) == toset(keys(jsondecode(file("../access/testdata/uat.json")).bastion)) &&
      toset(keys(output.uat.subnets)) == toset(keys(jsondecode(file("../access/testdata/uat.json")).subnets)) &&
      toset(keys(output.uat.subnets.dmz)) == toset(keys(jsondecode(file("../access/testdata/uat.json")).subnets.dmz))
    )
    error_message = "uat/access/testdata/uat.json no longer has the shape of output uat"
  }
}

run "network_rules" {
  command = apply

  # Workload NSGs: only the documented allows, then the deny tail.
  assert {
    condition     = toset([for r in azurerm_network_security_group.subnet["tenants"].security_rule : r.name if r.direction == "Inbound" && r.access == "Allow"]) == toset(["AllowBastionAdminIn"])
    error_message = "tenants: the only inbound allow is from the Bastion"
  }

  assert {
    condition = alltrue([for r in azurerm_network_security_group.subnet["tenants"].security_rule :
      r.source_address_prefix == "10.60.4.0/26" && toset(r.destination_port_ranges) == toset(["22", "5986"])
    if r.name == "AllowBastionAdminIn"])
    error_message = "tenants: Bastion reaches SSH and WinRM over HTTPS only"
  }

  assert {
    condition     = toset([for r in azurerm_network_security_group.subnet["tenants"].security_rule : r.name if r.direction == "Outbound" && r.access == "Allow"]) == toset(["AllowEnvoyPrivateOut"])
    error_message = "tenants: sprouts reach only Envoy, on the DMZ private range"
  }

  assert {
    condition = alltrue([for r in azurerm_network_security_group.subnet["tenants"].security_rule :
      r.destination_port_range == "8443"
    if startswith(r.name, "AllowEnvoy")])
    error_message = "tenants: Envoy is reached on 8443 only"
  }

  assert {
    condition = anytrue([for r in azurerm_network_security_group.subnet["tenants"].security_rule :
      r.name == "DenyCorePublicOut" && r.access == "Deny" && r.destination_address_prefix == "198.51.100.10/32" && r.priority < 4000
    ])
    error_message = "tenants: a sprout must not reach core's public address"
  }

  assert {
    condition     = toset([for r in azurerm_network_security_group.subnet["core"].security_rule : r.name if r.direction == "Inbound" && r.access == "Allow"]) == toset(["AllowBastionSshKubeIn", "AllowDmzFarmerApiIn", "AllowRunnerHttpsIn", "AllowDmzAccountsStoreIn"])
    error_message = "core: inbound only from the Bastion, the DMZ (farmer's API, the accounts store) and the runner"
  }

  assert {
    condition = alltrue([for r in azurerm_network_security_group.subnet["core"].security_rule :
      (r.name != "AllowRunnerHttpsIn" || (r.source_address_prefix == "203.0.113.7/32" && r.destination_port_range == "443")) &&
      (r.name != "AllowDmzFarmerApiIn" || (r.source_address_prefix == "10.60.1.0/24" && r.destination_port_range == "5405")) &&
      (r.name != "AllowDmzAccountsStoreIn" || (r.source_address_prefix == "10.60.1.0/24" && r.destination_port_range == "9000")) &&
      (r.name != "AllowBusOut" || (r.destination_address_prefix == "10.60.1.0/24" && r.destination_port_range == "8442"))
    ])
    error_message = "core: runner on 443, DMZ on 5405 and the accounts store 9000, out to the bus node port 8442"
  }

  assert {
    condition     = toset([for r in azurerm_network_security_group.subnet["dmz"].security_rule : r.name if r.direction == "Inbound" && r.access == "Allow"]) == toset(["AllowBastionSshKubeIn", "AllowSproutsEnvoyPrivateIn", "AllowRunnerEnvoyIn", "AllowCoreBusIn"])
    error_message = "dmz: inbound only from the Bastion, sprouts, the runner and core"
  }

  assert {
    condition = alltrue([for r in azurerm_network_security_group.subnet["dmz"].security_rule :
      (r.name != "AllowCoreBusIn" || (r.source_address_prefix == "10.60.2.0/24" && r.destination_port_range == "8442")) &&
      (r.name != "AllowSproutsEnvoyPrivateIn" || (r.source_address_prefix == "10.60.3.0/24" && r.destination_port_range == "8443")) &&
      (r.name != "AllowRunnerEnvoyIn" || (r.source_address_prefix == "203.0.113.7/32" && r.destination_port_range == "8443")) &&
      (r.name != "AllowFarmerApiOut" || (r.destination_address_prefix == "10.60.2.0/24" && r.destination_port_range == "5405")) &&
      (r.name != "AllowAccountsStoreOut" || (r.destination_address_prefix == "10.60.2.0/24" && r.destination_port_range == "9000"))
    ])
    error_message = "dmz: core in on 8442, sprouts and runner in on 8443, out to farmer on 5405 and the accounts store on 9000"
  }

  # Design D22: exactly two DMZ-to-core paths, farmer's API and the accounts
  # store, and nothing else.
  assert {
    condition     = toset([for r in azurerm_network_security_group.subnet["dmz"].security_rule : r.name if r.direction == "Outbound" && r.access == "Allow"]) == toset(["AllowFarmerApiOut", "AllowAccountsStoreOut"])
    error_message = "dmz: outbound only to farmer's API and the accounts store"
  }

  # No workload NSG admits SSH, WinRM or the Kubernetes API from anything but
  # AzureBastionSubnet.
  assert {
    condition = alltrue(flatten([for n in ["dmz", "core", "tenants"] : [
      for r in azurerm_network_security_group.subnet[n].security_rule :
      r.source_address_prefix == "10.60.4.0/26"
      if r.direction == "Inbound" && r.access == "Allow" && length(setintersection(toset(concat(r.destination_port_ranges == null ? [] : tolist(r.destination_port_ranges), r.destination_port_range == null ? [] : [r.destination_port_range])), toset(["22", "5985", "5986", "6443", "*"]))) > 0
    ]]))
    error_message = "management ports must be open to the Bastion subnet only"
  }

  # Every workload NSG overrides Azure's allow-VNet defaults.
  assert {
    condition = alltrue([for n in ["dmz", "core", "tenants"] :
      length([for r in azurerm_network_security_group.subnet[n].security_rule : r if contains(["DenyVnetIn", "DenyAllIn", "DenyVnetOut"], r.name) && r.access == "Deny"]) == 3
    ])
    error_message = "each workload NSG needs the deny tail"
  }

  assert {
    condition = anytrue([for r in azurerm_network_security_group.subnet["bastion"].security_rule :
      r.name == "AllowHttpsInbound" && r.source_address_prefix == "203.0.113.7/32" && r.destination_port_range == "443"
    ])
    error_message = "bastion: 443 from the runner only"
  }

  assert {
    condition = anytrue([for r in azurerm_network_security_group.subnet["tenants"].security_rule :
      r.name == "DenyDmzPublicOut" && r.access == "Deny" && r.destination_address_prefix == "198.51.100.10/32" && r.priority < 4000
    ])
    error_message = "tenants: sprouts use the DMZ private address, never its public one"
  }

  assert {
    condition = alltrue(flatten([for n in ["dmz", "core", "tenants", "bastion"] : [
      for r in azurerm_network_security_group.subnet[n].security_rule : !contains(["5406", "5407"], coalesce(r.destination_port_range, "x"))
    ]]))
    error_message = "the bus is reached on its node port 8442 only; 5406 and 5407 stay inside the DMZ"
  }

  assert {
    condition     = azurerm_subnet_network_security_group_association.bastion.subnet_id == azurerm_subnet.bastion.id
    error_message = "the Bastion NSG is always attached (fails closed)"
  }
}

# Envoy's port is 8443 by the owner's decision; if it ever changes (a load
# balancer in front), every Envoy rule must follow envoy_port.
run "envoy_port_moves_every_envoy_rule" {
  command = apply

  variables {
    envoy_port = 443
  }

  assert {
    condition = alltrue(flatten([for n in ["dmz", "tenants"] : [
      for r in azurerm_network_security_group.subnet[n].security_rule : r.destination_port_range == "443"
      if strcontains(r.name, "Envoy")
    ]])) && length(flatten([for n in ["dmz", "tenants"] : [for r in azurerm_network_security_group.subnet[n].security_rule : r if strcontains(r.name, "Envoy")]])) == 3
    error_message = "all three Envoy rules must use envoy_port"
  }
}

run "keep_hours_pushes_expiry" {
  command = apply

  variables {
    keep_hours = 24
  }

  assert {
    condition     = timecmp(azurerm_resource_group.run.tags["expires_at"], timeadd(plantimestamp(), "27h")) > 0
    error_message = "expires_at must be the first apply + run_budget_hours (4) + keep_hours"
  }
}

run "alma_plan_opt_in" {
  command = apply

  variables {
    alma_image_has_plan = true
  }

  assert {
    condition = (
      length(azurerm_linux_virtual_machine.sprout["t1-alma"].plan) == 1 &&
      azurerm_linux_virtual_machine.sprout["t1-alma"].plan[0].product == "almalinux-x86_64" &&
      length(azurerm_linux_virtual_machine.sprout["t1-ubuntu"].plan) == 0
    )
    error_message = "alma_image_has_plan = true puts the plan on the AlmaLinux sprouts only"
  }
}

run "bad_run_id" {
  command = plan

  variables {
    run_id = "ABC-1"
  }

  expect_failures = [var.run_id]
}

run "bad_runner_cidr" {
  command = plan

  variables {
    runner_cidr = "0.0.0.0/0"
  }

  expect_failures = [var.runner_cidr]
}

run "bad_release_tag" {
  command = plan

  variables {
    release_tag = "latest"
  }

  expect_failures = [var.release_tag]
}

# The HA run (owner, 2026-10-13): 3 core nodes of Standard_D4s_v5 and 3 DMZ
# nodes of Standard_D2s_v5, spread over the region's three zones, each hub
# behind an internal load balancer (k0s API and private ports) and a public
# one (the runner's port).
run "ha_three_plus_three" {
  command = apply

  variables {
    core_node_count = 3
    dmz_node_count  = 3
    core_node_size  = "Standard_D4s_v5"
  }

  assert {
    condition = (
      toset(keys(azurerm_linux_virtual_machine.hub)) == toset(["uat-core-1", "uat-core-2", "uat-core-3", "uat-dmz-1", "uat-dmz-2", "uat-dmz-3"]) &&
      alltrue([for n in ["uat-core-1", "uat-core-2", "uat-core-3"] : azurerm_linux_virtual_machine.hub[n].size == "Standard_D4s_v5" && azurerm_linux_virtual_machine.hub[n].os_disk[0].disk_size_gb == 128]) &&
      alltrue([for n in ["uat-dmz-1", "uat-dmz-2", "uat-dmz-3"] : azurerm_linux_virtual_machine.hub[n].size == "Standard_D2s_v5" && azurerm_linux_virtual_machine.hub[n].os_disk[0].disk_size_gb == 64])
    )
    error_message = "HA: three core nodes of D4s_v5 and three DMZ nodes of D2s_v5, named uat-<hub>-1 to 3"
  }

  assert {
    condition     = azurerm_bastion_host.uat.ip_connect_enabled == true
    error_message = "HA: the Bastion allows IP-based connections (the tunnel to each hub's api_address, uat/access)"
  }

  assert {
    condition = (
      tolist([for n in ["uat-core-1", "uat-core-2", "uat-core-3"] : azurerm_linux_virtual_machine.hub[n].zone]) == tolist(["1", "2", "3"]) &&
      tolist([for n in ["uat-dmz-1", "uat-dmz-2", "uat-dmz-3"] : azurerm_linux_virtual_machine.hub[n].zone]) == tolist(["1", "2", "3"]) &&
      alltrue([for v in values(azurerm_linux_virtual_machine.sprout) : v.zone == null])
    )
    error_message = "HA: each hub's nodes go one per zone; sprouts stay unzoned"
  }

  assert {
    condition = (
      length(azurerm_linux_virtual_machine.sprout) == 4 && length(azurerm_windows_virtual_machine.sprout) == 2 &&
      length(azurerm_public_ip.hub) == 6 &&
      alltrue([for p in values(azurerm_public_ip.hub) : p.domain_name_label == null]) &&
      azurerm_public_ip.hub_lb["dmz"].domain_name_label == "uatabc123-dmz" &&
      azurerm_public_ip.hub_lb["core"].domain_name_label == "uatabc123-core" &&
      alltrue([for p in values(azurerm_public_ip.hub_lb) : p.sku == "Standard" && p.allocation_method == "Static" && toset(p.zones) == toset(["1", "2", "3"])])
    )
    error_message = "HA: the hub DNS labels move to zone-redundant load balancer IPs; node IPs are outbound only"
  }

  assert {
    condition = (
      alltrue([for lb in concat(values(azurerm_lb.internal), values(azurerm_lb.public)) : lb.sku == "Standard"]) &&
      azurerm_lb.internal["core"].frontend_ip_configuration[0].private_ip_address == "10.60.2.250" &&
      azurerm_lb.internal["dmz"].frontend_ip_configuration[0].private_ip_address == "10.60.1.250" &&
      azurerm_lb.internal["dmz"].frontend_ip_configuration[0].private_ip_address_allocation == "Static" &&
      toset(azurerm_lb.internal["dmz"].frontend_ip_configuration[0].zones) == toset(["1", "2", "3"]) &&
      azurerm_lb.internal["core"].name == "uat-core-ilb" && azurerm_lb.public["dmz"].name == "uat-dmz-lb"
    )
    error_message = "HA: per hub a Standard internal load balancer on host .250 of its subnet and a Standard public one"
  }

  assert {
    condition = toset(keys(azurerm_lb_rule.hub)) == toset([
      "core-internal-6443", "core-internal-5405", "core-internal-9000", "core-public-443",
      "dmz-internal-6443", "dmz-internal-8443", "dmz-internal-8442", "dmz-public-8443",
    ])
    error_message = "HA: the k0s API and each hub's private ports on the internal load balancer, the runner's port on the public one"
  }

  assert {
    condition = alltrue([for k, r in azurerm_lb_rule.hub :
      r.protocol == "Tcp" && r.frontend_port == r.backend_port && r.disable_outbound_snat &&
      azurerm_lb_probe.hub[k].port == r.backend_port && azurerm_lb_probe.hub[k].protocol == "Tcp" &&
      r.frontend_ip_configuration_name == (strcontains(k, "-internal-") ? "internal" : "public")
    ])
    error_message = "HA: every rule is TCP, port to the same port, with a TCP probe on that port and no outbound SNAT"
  }

  assert {
    condition = (
      length(azurerm_network_interface_backend_address_pool_association.hub) == 12 &&
      length(azurerm_lb_backend_address_pool.hub) == 4 &&
      toset(keys(azurerm_network_interface_backend_address_pool_association.hub)) == toset(flatten([
        for n in ["uat-core-1", "uat-core-2", "uat-core-3", "uat-dmz-1", "uat-dmz-2", "uat-dmz-3"] : ["${n}-internal", "${n}-public"]
      ]))
    )
    error_message = "HA: every node of a hub is in both of its hub's backend pools"
  }

  # NSG: node to node inside each hub and the probes, on top of every
  # single-node rule.
  assert {
    condition = alltrue([for n in ["dmz", "core"] :
      length([for r in azurerm_network_security_group.subnet[n].security_rule : r if contains(["AllowHubNodesTcpIn", "AllowHubNodesUdpIn", "AllowLoadBalancerProbeIn", "AllowHubNodesTcpOut", "AllowHubNodesUdpOut"], r.name)]) == 5
    ])
    error_message = "HA: each hub NSG adds node-to-node rules both ways and the probe rule"
  }

  assert {
    condition = (
      toset([for r in azurerm_network_security_group.subnet["core"].security_rule : r.name if r.direction == "Inbound" && r.access == "Allow"]) == toset(["AllowBastionSshKubeIn", "AllowDmzFarmerApiIn", "AllowRunnerHttpsIn", "AllowDmzAccountsStoreIn", "AllowHubNodesTcpIn", "AllowHubNodesUdpIn", "AllowLoadBalancerProbeIn"]) &&
      toset([for r in azurerm_network_security_group.subnet["dmz"].security_rule : r.name if r.direction == "Inbound" && r.access == "Allow"]) == toset(["AllowBastionSshKubeIn", "AllowSproutsEnvoyPrivateIn", "AllowRunnerEnvoyIn", "AllowCoreBusIn", "AllowHubNodesTcpIn", "AllowHubNodesUdpIn", "AllowLoadBalancerProbeIn"]) &&
      toset([for r in azurerm_network_security_group.subnet["dmz"].security_rule : r.name if r.direction == "Outbound" && r.access == "Allow"]) == toset(["AllowFarmerApiOut", "AllowAccountsStoreOut", "AllowHubNodesTcpOut", "AllowHubNodesUdpOut"])
    )
    error_message = "HA: every single-node rule is kept, and only the node-to-node and probe rules are added"
  }

  assert {
    condition = alltrue(flatten([for n in ["dmz", "core"] : [
      for r in azurerm_network_security_group.subnet[n].security_rule : (
        (r.name != "AllowHubNodesTcpIn" && r.name != "AllowHubNodesTcpOut") ||
        (r.protocol == "Tcp" && r.source_address_prefix == (n == "dmz" ? "10.60.1.0/24" : "10.60.2.0/24") && r.destination_address_prefix == r.source_address_prefix &&
        toset(r.destination_port_ranges) == toset(["179", "2379-2380", "6443", "8132", "9443", "10250"]))
        ) && (
        (r.name != "AllowHubNodesUdpIn" && r.name != "AllowHubNodesUdpOut") ||
        (r.protocol == "Udp" && r.source_address_prefix == r.destination_address_prefix && r.destination_port_range == "5555")
      )
    ]]))
    error_message = "HA: node to node inside the hub only: etcd 2379-2380, API 6443, join 9443, konnectivity 8132, kubelet 10250, kube-router BGP 179 and FOU 5555/udp"
  }

  assert {
    condition = (
      anytrue([for r in azurerm_network_security_group.subnet["core"].security_rule :
        r.name == "AllowLoadBalancerProbeIn" && r.source_address_prefix == "AzureLoadBalancer" && toset(r.destination_port_ranges) == toset(["6443", "5405", "9000", "443"])
      ]) &&
      anytrue([for r in azurerm_network_security_group.subnet["dmz"].security_rule :
        r.name == "AllowLoadBalancerProbeIn" && r.source_address_prefix == "AzureLoadBalancer" && toset(r.destination_port_ranges) == toset(["6443", "8443", "8442"])
      ])
    )
    error_message = "HA: the health probes reach exactly the load-balanced ports"
  }

  # Management ports still only from the Bastion, apart from the hub's own
  # nodes (etcd and API peers) and the load balancer's probe.
  assert {
    condition = alltrue(flatten([for n in ["dmz", "core", "tenants"] : [
      for r in azurerm_network_security_group.subnet[n].security_rule :
      contains(["10.60.4.0/26", "AzureLoadBalancer", n == "dmz" ? "10.60.1.0/24" : (n == "core" ? "10.60.2.0/24" : "none")], r.source_address_prefix)
      if r.direction == "Inbound" && r.access == "Allow" && length(setintersection(toset(concat(r.destination_port_ranges == null ? [] : tolist(r.destination_port_ranges), r.destination_port_range == null ? [] : [r.destination_port_range])), toset(["22", "5985", "5986", "6443", "*"]))) > 0
    ]]))
    error_message = "HA: management ports open to the Bastion, the hub's own nodes and the load balancer probe only"
  }

  assert {
    condition = (
      toset(azurerm_private_dns_a_record.hub["dmz"].records) == toset(["10.60.1.250"]) &&
      toset(azurerm_private_dns_a_record.hub["core"].records) == toset(["10.60.2.250"]) &&
      toset(azurerm_private_dns_a_record.hub_api["dmz"].records) == toset(["10.60.1.250"]) &&
      toset(azurerm_private_dns_a_record.hub_api["core"].records) == toset(["10.60.2.250"]) &&
      toset(keys(azurerm_private_dns_a_record.hub_node)) == toset(["uat-core-1", "uat-core-2", "uat-core-3", "uat-dmz-1", "uat-dmz-2", "uat-dmz-3"])
    )
    error_message = "HA: <hub> and <hub>-api resolve to the internal load balancer, and every node has its own record"
  }

  assert {
    condition = (
      toset(keys(output.uat)) == toset(["run_id", "region", "resource_group", "dmz", "core", "sprouts", "bastion", "subnets"]) &&
      tolist(output.uat.core.node_names) == tolist(["uat-core-1", "uat-core-2", "uat-core-3"]) &&
      tolist(output.uat.dmz.node_names) == tolist(["uat-dmz-1", "uat-dmz-2", "uat-dmz-3"]) &&
      length(output.uat.core.node_ids) == 3 && length(output.uat.dmz.node_private_ips) == 3 &&
      output.uat.core.name == "uat-core-1" &&
      output.uat.core.api_address == "10.60.2.250" &&
      output.uat.dmz.api_address == "10.60.1.250" &&
      output.uat.dmz.api_fqdn == "dmz-api.uat.imas.internal" &&
      tolist(output.ha_node_names.core) == tolist(["uat-core-1", "uat-core-2", "uat-core-3"]) &&
      tolist(output.ha_node_names.dmz) == tolist(["uat-dmz-1", "uat-dmz-2", "uat-dmz-3"])
    )
    error_message = "HA: uat keeps the contract's keys and lists every node, the API addresses, and the VMs the HA tests stop"
  }

  # uat/access/testdata/uat-ha.json is the HA sample the access scripts test
  # against; it must keep the shape of the real HA output.
  assert {
    condition = (
      toset(keys(output.uat)) == toset(keys(jsondecode(file("../access/testdata/uat-ha.json")))) &&
      toset(keys(output.uat.dmz)) == toset(keys(jsondecode(file("../access/testdata/uat-ha.json")).dmz)) &&
      toset(keys(output.uat.core)) == toset(keys(jsondecode(file("../access/testdata/uat-ha.json")).core)) &&
      length(jsondecode(file("../access/testdata/uat-ha.json")).core.node_names) == length(output.uat.core.node_names)
    )
    error_message = "uat/access/testdata/uat-ha.json no longer has the shape of the HA output uat"
  }
}

# Both variable sets plan (brief H1: tofu plan with the single-node and the HA
# variables).
run "ha_plan" {
  command = plan

  variables {
    core_node_count = 3
    dmz_node_count  = 3
    core_node_size  = "Standard_D4s_v5"
  }

  assert {
    condition     = length(azurerm_linux_virtual_machine.hub) == 6 && length(azurerm_lb_rule.hub) == 8
    error_message = "the HA variables plan six hub nodes and eight load-balancing rules"
  }
}

run "single_node_plan" {
  command = plan

  assert {
    condition     = length(azurerm_linux_virtual_machine.hub) == 2 && length(azurerm_lb_rule.hub) == 0
    error_message = "the default variables plan one node per hub and no load balancer"
  }
}

# A region without zones: the nodes and load balancer frontends get none.
run "ha_region_without_zones" {
  command = apply

  variables {
    core_node_count = 3
    dmz_node_count  = 3
  }

  override_data {
    target = data.azurerm_location.run
    values = {
      zone_mappings = []
    }
  }

  assert {
    condition = (
      alltrue([for v in values(azurerm_linux_virtual_machine.hub) : v.zone == null]) &&
      alltrue([for p in values(azurerm_public_ip.hub_lb) : p.zones == null || length(p.zones) == 0]) &&
      alltrue([for lb in values(azurerm_lb.internal) : lb.frontend_ip_configuration[0].zones == null || length(lb.frontend_ip_configuration[0].zones) == 0])
    )
    error_message = "without zones in the region, nothing is zonal"
  }
}

# Only one hub in HA: the other keeps its single node, load balancer free.
run "ha_core_only" {
  command = apply

  variables {
    core_node_count = 3
  }

  assert {
    condition = (
      toset(keys(azurerm_lb.internal)) == toset(["core"]) &&
      tolist(output.uat.dmz.node_names) == tolist(["uat-dmz"]) &&
      length(output.ha_node_names.dmz) == 0 &&
      length(output.ha_node_names.core) == 3 &&
      length([for r in azurerm_network_security_group.subnet["dmz"].security_rule : r if startswith(r.name, "AllowHubNodes")]) == 0
    )
    error_message = "a hub of one node is unchanged when the other hub is HA"
  }

  assert {
    condition     = azurerm_bastion_host.uat.ip_connect_enabled == true
    error_message = "one HA hub is enough for the Bastion's IP-based connection"
  }
}

run "bad_core_node_count" {
  command = plan

  variables {
    core_node_count = 2
  }

  expect_failures = [var.core_node_count]
}

run "bad_dmz_node_count" {
  command = plan

  variables {
    dmz_node_count = 0
  }

  expect_failures = [var.dmz_node_count]
}
