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
      azurerm_public_ip.hub["dmz"].domain_name_label == "uatabc123-dmz" &&
      azurerm_public_ip.hub["core"].domain_name_label == "uatabc123-core"
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
      azurerm_bastion_host.uat.shareable_link_enabled == false
    )
    error_message = "Bastion must be Standard with native client tunnelling on"
  }

  assert {
    condition = (
      azurerm_linux_virtual_machine.hub["dmz"].size == "Standard_D2s_v5" &&
      azurerm_linux_virtual_machine.hub["core"].size == "Standard_D8s_v5" &&
      azurerm_linux_virtual_machine.hub["dmz"].os_disk[0].disk_size_gb == 64 &&
      azurerm_linux_virtual_machine.hub["core"].os_disk[0].disk_size_gb == 128 &&
      azurerm_linux_virtual_machine.hub["core"].os_disk[0].storage_account_type == "StandardSSD_LRS"
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
    condition     = toset([for r in azurerm_network_security_group.subnet["core"].security_rule : r.name if r.direction == "Inbound" && r.access == "Allow"]) == toset(["AllowBastionSshKubeIn", "AllowDmzFarmerApiIn", "AllowRunnerHttpsIn"])
    error_message = "core: inbound only from the Bastion, the DMZ and the runner"
  }

  assert {
    condition = alltrue([for r in azurerm_network_security_group.subnet["core"].security_rule :
      (r.name != "AllowRunnerHttpsIn" || (r.source_address_prefix == "203.0.113.7/32" && r.destination_port_range == "443")) &&
      (r.name != "AllowDmzFarmerApiIn" || (r.source_address_prefix == "10.60.1.0/24" && r.destination_port_range == "5405")) &&
      (r.name != "AllowBusOut" || (r.destination_address_prefix == "10.60.1.0/24" && r.destination_port_range == "8442"))
    ])
    error_message = "core: runner on 443, DMZ on 5405, out to the bus node port 8442"
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
      (r.name != "AllowFarmerApiOut" || (r.destination_address_prefix == "10.60.2.0/24" && r.destination_port_range == "5405"))
    ])
    error_message = "dmz: core in on 8442, sprouts and runner in on 8443, out to farmer on 5405"
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
