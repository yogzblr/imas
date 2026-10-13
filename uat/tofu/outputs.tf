# tofu output -json uat is the interface to every other UAT brief (Shared
# contract, section 4h), with exactly the contract's keys (owner, 2026-10-06).
# It holds no credential, so it is not sensitive.
#
# Each hub object keeps the contract's fields: name, id and private_ip are
# the hub's first node (its only node in the single-node run), public_ip and
# fqdn what the runner reaches (the node's public IP, or the public load
# balancer's on an HA hub). P24 adds, for any node count: node_names,
# node_ids and node_private_ips (lists in node order), api_address (the k0s
# API's stable private address: the node's own, or the internal load
# balancer's) and api_fqdn (<hub>-api.<zone>, which resolves to it).
locals {
  hub_output = {
    for k, h in local.hubs : k => {
      name             = azurerm_linux_virtual_machine.hub[local.hub_node_names[k][0]].name
      id               = azurerm_linux_virtual_machine.hub[local.hub_node_names[k][0]].id
      private_ip       = azurerm_network_interface.hub[local.hub_node_names[k][0]].private_ip_address
      public_ip        = local.public_ip[k]
      fqdn             = local.public_fqdn[k]
      admin_user       = var.admin_user
      node_names       = [for n in local.hub_node_names[k] : azurerm_linux_virtual_machine.hub[n].name]
      node_ids         = [for n in local.hub_node_names[k] : azurerm_linux_virtual_machine.hub[n].id]
      node_private_ips = [for n in local.hub_node_names[k] : azurerm_network_interface.hub[n].private_ip_address]
      api_address      = local.api_address[k]
      api_fqdn         = "${azurerm_private_dns_a_record.hub_api[k].name}.${azurerm_private_dns_zone.uat.name}"
    }
  }
}
output "uat" {
  description = "The uat object of the Shared contract: run, hubs, sprouts, Bastion and subnets. No credentials."
  value = {
    run_id         = var.run_id
    region         = azurerm_resource_group.run.location
    resource_group = azurerm_resource_group.run.name

    dmz  = local.hub_output.dmz
    core = local.hub_output.core

    sprouts = {
      for name, s in local.sprouts : name => {
        tenant     = s.tenant
        os         = s.os
        connection = s.os == "windows" ? "winrm" : "ssh"
        id         = s.os == "windows" ? azurerm_windows_virtual_machine.sprout[name].id : azurerm_linux_virtual_machine.sprout[name].id
        private_ip = azurerm_network_interface.sprout[name].private_ip_address
        public_ip  = azurerm_public_ip.sprout[name].ip_address
        admin_user = var.admin_user
      }
    }

    bastion = {
      name = azurerm_bastion_host.uat.name
      id   = azurerm_bastion_host.uat.id
    }

    subnets = {
      dmz     = { cidr = local.cidr.dmz, id = azurerm_subnet.workload["dmz"].id }
      core    = { cidr = local.cidr.core, id = azurerm_subnet.workload["core"].id }
      tenants = { cidr = local.cidr.tenants, id = azurerm_subnet.workload["tenants"].id }
      bastion = { cidr = local.cidr.bastion, id = azurerm_subnet.bastion.id }
    }
  }
}

# The VMs the HA tests stop and start (uat/tests, tier ha): every node of an
# HA hub, per hub, in node order. A hub of one node has none (stopping it
# takes the hub down). Not part of uat, whose top-level keys the Shared
# contract fixes; the workflow writes it next to uat.json.
output "ha_node_names" {
  description = "Per hub (core, dmz), the names of the VMs the HA tests may stop: every node of a hub with more than one node; an empty list for a single-node hub."
  value = {
    for k, h in local.hubs : k => h.count > 1 ? local.hub_output[k].node_names : []
  }
}

# Credentials: never part of uat, never printed by tofu output (sensitive).
# Owner, 2026-10-06: sensitive outputs are the accepted way to hand them over.
# The workflow reads them with tofu output -raw into 0600 files that are never
# uploaded as artifacts. They also live in this run's state blob.

output "ssh_private_key" {
  description = "Per-run SSH private key (OpenSSH format) for admin_user on every Linux VM."
  value       = tls_private_key.ssh.private_key_openssh
  sensitive   = true
}

output "windows_admin_password" {
  description = "Per-run random password for admin_user on both Windows sprouts (WinRM over HTTPS)."
  value       = random_password.windows_admin.result
  sensitive   = true
}

# The HA run's object store (object-store.tf): the Azure Blob account the
# farmer chart's Versity Gateway serves as S3. null in the single-node run
# (RustFS on the core hub). Not part of uat, whose top-level keys the Shared
# contract fixes; the workflow writes it next to uat.json. No credential.
output "object_store" {
  description = "The HA run's Azure Blob account for Versity Gateway: account_name and blob_endpoint; null when the core hub has one node."
  value = local.object_store_enabled ? {
    account_name  = azurerm_storage_account.object_store[0].name
    blob_endpoint = azurerm_storage_account.object_store[0].primary_blob_endpoint
  } : null
}

output "object_store_account_key" {
  description = "The HA run's Azure Blob account key (versity.azure.credentialsSecret); empty when the core hub has one node."
  value       = local.object_store_enabled ? azurerm_storage_account.object_store[0].primary_access_key : ""
  sensitive   = true
}
