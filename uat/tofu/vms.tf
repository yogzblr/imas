# Eight VMs and one Azure Bastion. Every public IP is Standard and static.
# The hubs' public IPs carry the DNS labels from the Shared contract and take
# the runner's traffic to Envoy and to 443 on core; the sprouts' are for
# outbound traffic only (their NSG denies every inbound flow from the internet).
#
# Destroy: NICs and public IPs are their own resources, OS disks go with their
# VM (provider feature delete_os_disk_on_deletion), there are no data disks,
# and the whole resource group is deleted last, so destroy leaves nothing. See
# README.md, "Destroy semantics".

resource "azurerm_public_ip" "hub" {
  for_each = local.hubs

  name                = "${each.value.name}-pip"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = each.value.dns_label
  tags                = local.tags
}

resource "azurerm_public_ip" "sprout" {
  for_each = local.sprouts

  name                = "${each.key}-pip"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "hub" {
  for_each = local.hubs

  name                = "${each.value.name}-nic"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  tags                = local.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.workload[each.key].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.hub[each.key].id
  }

  # The subnet's NSG is in place before anything can use this NIC.
  depends_on = [azurerm_subnet_network_security_group_association.workload]
}

resource "azurerm_network_interface" "sprout" {
  for_each = local.sprouts

  name                = "${each.key}-nic"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  tags                = local.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.workload["tenants"].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.sprout[each.key].id
  }

  # The subnet's NSG is in place before anything can use this NIC.
  depends_on = [azurerm_subnet_network_security_group_association.workload]
}

# Hubs: Ubuntu 24.04, single-node k0s each (UAT.2). Standard SSD OS disks.
# No ephemeral OS disk: Dsv5 sizes have no local temp disk or cache to hold one.
resource "azurerm_linux_virtual_machine" "hub" {
  for_each = local.hubs

  name                            = each.value.name
  computer_name                   = each.value.name
  location                        = azurerm_resource_group.run.location
  resource_group_name             = azurerm_resource_group.run.name
  size                            = each.value.size
  admin_username                  = var.admin_user
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.hub[each.key].id]
  tags                            = local.tags

  admin_ssh_key {
    username   = var.admin_user
    public_key = tls_private_key.ssh.public_key_openssh
  }

  os_disk {
    name                 = "${each.value.name}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = each.value.disk_gb
  }

  source_image_reference {
    publisher = local.images.ubuntu[0]
    offer     = local.images.ubuntu[1]
    sku       = local.images.ubuntu[2]
    version   = local.images.ubuntu[3]
  }

  # Managed boot diagnostics: a serial console log for debugging a VM that
  # never answers on its tunnel. No storage account to clean up.
  boot_diagnostics {}
}

# Linux sprouts: Ubuntu 24.04 and AlmaLinux 9. Small Standard SSD OS disks, no
# data disks. No ephemeral OS disk: the B-series v2 sizes have no
# local temp disk to hold one.
resource "azurerm_linux_virtual_machine" "sprout" {
  for_each = local.linux_sprouts

  name                            = each.key
  computer_name                   = each.key
  location                        = azurerm_resource_group.run.location
  resource_group_name             = azurerm_resource_group.run.name
  size                            = var.linux_sprout_size
  admin_username                  = var.admin_user
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.sprout[each.key].id]
  tags                            = local.tags

  admin_ssh_key {
    username   = var.admin_user
    public_key = tls_private_key.ssh.public_key_openssh
  }

  os_disk {
    name                 = "${each.key}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.sprout_os_disk_gb
  }

  source_image_reference {
    publisher = local.images[each.value.os][0]
    offer     = local.images[each.value.os][1]
    sku       = local.images[each.value.os][2]
    version   = local.images[each.value.os][3]
  }

  # Off by default (alma_image_has_plan): Azure refuses almalinux:almalinux-x86_64:9-gen2
  # with a plan ("doesn't require plan information"). The owner still accepts the
  # marketplace terms once per subscription.
  dynamic "plan" {
    for_each = each.value.os == "alma" && var.alma_image_has_plan ? [1] : []
    content {
      publisher = local.images.alma[0]
      product   = local.images.alma[1]
      name      = local.images.alma[2]
    }
  }

  boot_diagnostics {}
}

# Windows sprouts: Server 2022 Core smalldisk. No ephemeral OS disk: the B-series v2
# sizes have no local temp disk to hold one.
resource "azurerm_windows_virtual_machine" "sprout" {
  for_each = local.windows_sprouts

  name                  = each.key
  computer_name         = each.key
  location              = azurerm_resource_group.run.location
  resource_group_name   = azurerm_resource_group.run.name
  size                  = var.windows_sprout_size
  admin_username        = var.admin_user
  admin_password        = random_password.windows_admin.result
  network_interface_ids = [azurerm_network_interface.sprout[each.key].id]
  provision_vm_agent    = true
  tags                  = local.tags

  # No Windows Update reboot in the middle of a run.
  patch_mode                = "Manual"
  automatic_updates_enabled = false

  os_disk {
    name                 = "${each.key}-osdisk"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.sprout_os_disk_gb
  }

  source_image_reference {
    publisher = local.images.windows[0]
    offer     = local.images.windows[1]
    sku       = local.images.windows[2]
    version   = local.images.windows[3]
  }

  boot_diagnostics {}
}

# WinRM over HTTPS on 5986 (winrm-https.ps1). The command goes in
# protected_settings so it is not shown in the VM's instance view; it holds no
# secret.
locals {
  winrm_script = join("\n", [
    for l in split("\n", file("${path.module}/winrm-https.ps1")) : l
    if !startswith(trimspace(l), "#") && trimspace(l) != ""
  ])
}

resource "azurerm_virtual_machine_extension" "winrm_https" {
  for_each = local.windows_sprouts

  name                       = "winrm-https"
  virtual_machine_id         = azurerm_windows_virtual_machine.sprout[each.key].id
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  auto_upgrade_minor_version = true
  tags                       = local.tags

  # Comment lines are dropped to keep the command line well under Windows'
  # 8191 character limit.
  protected_settings = jsonencode({
    commandToExecute = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${textencodebase64(local.winrm_script, "UTF-16LE")}"
  })
}

# Azure Bastion, Standard SKU, native client tunnelling on: the only path to
# SSH, WinRM and the Kubernetes API (uat/access/tunnels.sh).
resource "azurerm_public_ip" "bastion" {
  name                = "uat-bastion-pip"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_bastion_host" "uat" {
  name                   = "uat-bastion"
  location               = azurerm_resource_group.run.location
  resource_group_name    = azurerm_resource_group.run.name
  sku                    = "Standard"
  scale_units            = 2
  tunneling_enabled      = true
  copy_paste_enabled     = false
  file_copy_enabled      = false
  ip_connect_enabled     = false
  shareable_link_enabled = false
  tags                   = local.tags

  ip_configuration {
    name                 = "primary"
    subnet_id            = azurerm_subnet.bastion.id
    public_ip_address_id = azurerm_public_ip.bastion.id
  }

  # Azure checks the subnet's NSG when the Bastion is created.
  depends_on = [azurerm_subnet_network_security_group_association.bastion]
}
