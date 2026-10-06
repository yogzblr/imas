# tofu output -json uat is the interface to every other UAT brief (Shared
# contract, section 4h), with exactly the contract's keys (owner, 2026-10-06).
# It holds no credential, so it is not sensitive.
output "uat" {
  description = "The uat object of the Shared contract: run, hubs, sprouts, Bastion and subnets. No credentials."
  value = {
    run_id         = var.run_id
    region         = azurerm_resource_group.run.location
    resource_group = azurerm_resource_group.run.name

    dmz = {
      name       = azurerm_linux_virtual_machine.hub["dmz"].name
      id         = azurerm_linux_virtual_machine.hub["dmz"].id
      private_ip = azurerm_network_interface.hub["dmz"].private_ip_address
      public_ip  = azurerm_public_ip.hub["dmz"].ip_address
      fqdn       = azurerm_public_ip.hub["dmz"].fqdn
      admin_user = var.admin_user
    }

    core = {
      name       = azurerm_linux_virtual_machine.hub["core"].name
      id         = azurerm_linux_virtual_machine.hub["core"].id
      private_ip = azurerm_network_interface.hub["core"].private_ip_address
      public_ip  = azurerm_public_ip.hub["core"].ip_address
      fqdn       = azurerm_public_ip.hub["core"].fqdn
      admin_user = var.admin_user
    }

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
