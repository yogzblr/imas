# Load balancers of an HA hub (core_node_count or dmz_node_count above 1;
# P24, brief H-azure-next-runs.md H1). A hub of one node gets none: the
# single-node run is unchanged.
#
# Per HA hub, both Standard SKU, backend pool every node of the hub:
#   - internal (uat-<hub>-ilb): a static private address in the hub's subnet
#     (host .250), the stable address of the hub's k0s API (6443) and of the
#     hub's private ports (local.hubs[*].private_ports: Envoy and the bus
#     node port on the DMZ, farmer's API and the accounts store on core). The
#     private DNS names <hub>.<zone> and <hub>-api.<zone> point at it
#     (dns.tf), so sprouts, the other hub and the Bastion tunnels keep one
#     address while a node is stopped.
#   - public (uat-<hub>-lb): a zone-redundant Standard public IP carrying the
#     hub's DNS label (uat<run_id>-<hub>), for the runner's port
#     (local.hubs[*].public_ports: Envoy on the DMZ, 443 on core). It replaces
#     the single node's public IP for inbound traffic.
#
# Every rule is TCP with a TCP health probe on its own port, so a node where
# nothing listens on a port (a stopped VM, a hostPort pod on another node)
# drops out of that rule only. Outbound SNAT is off on every rule: each node
# keeps its own public IP for outbound traffic. Idle connections (NATS,
# WebSocket) are kept 30 minutes and reset with a TCP RST after that.
#
# Azure limitation: an internal load balancer drops a flow from a backend node
# to its own frontend when the flow lands on that same node, so a node of the
# hub must not use the internal address to reach its own hub's API (k0s
# node-local load balancing does not; brief H-azure-next-runs.md H2).

locals {
  # One entry per load-balancing rule: "<hub>-<internal|public>-<port>".
  lb_rules = merge([
    for k, h in local.ha_hubs : merge(
      { for p in distinct(concat([local.kube_api_port], h.private_ports)) : "${k}-internal-${p}" => { hub = k, lb = "internal", port = p } },
      { for p in distinct(h.public_ports) : "${k}-public-${p}" => { hub = k, lb = "public", port = p } },
    )
  ]...)

  # One entry per node and load balancer: "<node>-<internal|public>".
  lb_members = merge([
    for n, v in local.hub_nodes : {
      for lb in ["internal", "public"] : "${n}-${lb}" => { node = n, hub = v.hub, lb = lb }
    } if contains(keys(local.ha_hubs), v.hub)
  ]...)

  # The internal load balancer's static address: host .250 of the hub's
  # subnet, clear of the addresses Azure hands to NICs from .4 up.
  ilb_ip = { for k, h in local.ha_hubs : k => cidrhost(local.cidr[k], 250) }

  # Per hub: the stable private address of its k0s API (the internal load
  # balancer on an HA hub, the node's own address on a single node).
  api_address = {
    for k, h in local.hubs : k => h.count > 1 ? local.ilb_ip[k] : azurerm_network_interface.hub[local.hub_node_names[k][0]].private_ip_address
  }

  # Per hub: the address the runner reaches (public IP and FQDN).
  public_ip = {
    for k, h in local.hubs : k => h.count > 1 ? azurerm_public_ip.hub_lb[k].ip_address : azurerm_public_ip.hub[local.hub_node_names[k][0]].ip_address
  }
  public_fqdn = {
    for k, h in local.hubs : k => h.count > 1 ? azurerm_public_ip.hub_lb[k].fqdn : azurerm_public_ip.hub[local.hub_node_names[k][0]].fqdn
  }

  # Every public address of a hub (nodes and load balancer), for the tenants'
  # deny rules.
  hub_public_ips = {
    for k, h in local.hubs : k => distinct(concat(
      [for n in local.hub_node_names[k] : azurerm_public_ip.hub[n].ip_address],
      h.count > 1 ? [azurerm_public_ip.hub_lb[k].ip_address] : [],
    ))
  }
}

resource "azurerm_public_ip" "hub_lb" {
  for_each = local.ha_hubs

  name                = "${each.value.name}-lb-pip"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = each.value.dns_label
  zones               = length(local.zones) > 0 ? local.zones : null
  tags                = local.tags
}

resource "azurerm_lb" "public" {
  for_each = local.ha_hubs

  name                = "${each.value.name}-lb"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  sku                 = "Standard"
  tags                = local.tags

  frontend_ip_configuration {
    name                 = "public"
    public_ip_address_id = azurerm_public_ip.hub_lb[each.key].id
  }
}

resource "azurerm_lb" "internal" {
  for_each = local.ha_hubs

  name                = "${each.value.name}-ilb"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  sku                 = "Standard"
  tags                = local.tags

  frontend_ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.workload[each.key].id
    private_ip_address_allocation = "Static"
    private_ip_address            = local.ilb_ip[each.key]
    zones                         = length(local.zones) > 0 ? local.zones : null
  }

  depends_on = [azurerm_subnet_network_security_group_association.workload]
}

resource "azurerm_lb_backend_address_pool" "hub" {
  for_each = { for m in flatten([for k, h in local.ha_hubs : [for lb in ["internal", "public"] : { key = "${k}-${lb}", hub = k, lb = lb }]]) : m.key => m }

  name            = "${local.hubs[each.value.hub].name}-nodes"
  loadbalancer_id = each.value.lb == "internal" ? azurerm_lb.internal[each.value.hub].id : azurerm_lb.public[each.value.hub].id
}

resource "azurerm_network_interface_backend_address_pool_association" "hub" {
  for_each = local.lb_members

  network_interface_id    = azurerm_network_interface.hub[each.value.node].id
  ip_configuration_name   = "primary"
  backend_address_pool_id = azurerm_lb_backend_address_pool.hub["${each.value.hub}-${each.value.lb}"].id
}

resource "azurerm_lb_probe" "hub" {
  for_each = local.lb_rules

  name                = "tcp-${each.value.port}"
  loadbalancer_id     = each.value.lb == "internal" ? azurerm_lb.internal[each.value.hub].id : azurerm_lb.public[each.value.hub].id
  protocol            = "Tcp"
  port                = each.value.port
  interval_in_seconds = 5
  number_of_probes    = 2
}

resource "azurerm_lb_rule" "hub" {
  for_each = local.lb_rules

  name                           = "tcp-${each.value.port}"
  loadbalancer_id                = each.value.lb == "internal" ? azurerm_lb.internal[each.value.hub].id : azurerm_lb.public[each.value.hub].id
  frontend_ip_configuration_name = each.value.lb
  protocol                       = "Tcp"
  frontend_port                  = each.value.port
  backend_port                   = each.value.port
  backend_address_pool_ids       = [azurerm_lb_backend_address_pool.hub["${each.value.hub}-${each.value.lb}"].id]
  probe_id                       = azurerm_lb_probe.hub[each.key].id
  disable_outbound_snat          = true
  idle_timeout_in_minutes        = 30
  tcp_reset_enabled              = true
}
