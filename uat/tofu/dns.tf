# Owner, 2026-10-06: sprouts reach Envoy on the DMZ private IP through a
# private DNS name. An Azure Private DNS zone linked to the VNet answers
# dmz.<zone> and core.<zone> with the hubs' private addresses for every VM in
# the VNet (and for pods whose DNS forwards to the node's resolver). It is not
# resolvable from the internet. The name is a fixed convention, not part of
# the uat output, whose keys the Shared contract fixes.

resource "azurerm_private_dns_zone" "uat" {
  name                = var.private_dns_zone
  resource_group_name = azurerm_resource_group.run.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "uat" {
  name                  = "uat-vnet"
  resource_group_name   = azurerm_resource_group.run.name
  private_dns_zone_name = azurerm_private_dns_zone.uat.name
  virtual_network_id    = azurerm_virtual_network.uat.id
  registration_enabled  = false
  tags                  = local.tags
}

resource "azurerm_private_dns_a_record" "hub" {
  for_each = local.hubs

  name                = each.key
  zone_name           = azurerm_private_dns_zone.uat.name
  resource_group_name = azurerm_resource_group.run.name
  ttl                 = 60
  records             = [azurerm_network_interface.hub[each.key].private_ip_address]
  tags                = local.tags
}
