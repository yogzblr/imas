# One network security group per subnet. The rules, and the reason for each,
# are tabled in README.md ("Network rules"); keep the two in step.
#
# Azure's default rules allow all traffic inside the VNet (AllowVnetInBound and
# AllowVnetOutBound, priority 65000) and from the Azure load balancer. Each
# workload NSG therefore ends with explicit denies at 4000 (VirtualNetwork) and
# 4096 (everything inbound), so only the allow rules above them pass. NSGs are
# stateful: replies to an allowed flow need no rule of their own.

locals {
  runner = [var.runner_cidr]

  # Node to node inside an HA hub (P24): k0s's own ports (docs.k0sproject.io,
  # "Networking": etcd peer and client 2380 and 2379, the API 6443, the
  # controller join API 9443, konnectivity 8132, kubelet 10250) and the CNI
  # the k0s config uses, kube-router (uat/k0s/templates/k0sctl.yaml.tmpl):
  # BGP between the nodes on TCP 179 and its pod overlay. Azure drops
  # IP-in-IP inside a VNet, so the overlay is kube-router's FOU encapsulation
  # on UDP 5555 (its default port), not IPIP.
  k0s_node_tcp_ports = ["179", "2379-2380", "6443", "8132", "9443", "10250"]
  k0s_node_udp_ports = ["5555"]

  # The rules an HA hub adds to its NSG; none for a single node, whose NSG is
  # unchanged. AzureLoadBalancer is the health probes' source (168.63.129.16):
  # DenyAllIn would otherwise drop them, as it overrides Azure's
  # AllowAzureLoadBalancerInBound default.
  ha_rules = {
    for k, h in local.hubs : k => [for r in [
      { name = "AllowHubNodesTcpIn", priority = 150, direction = "Inbound", access = "Allow", protocol = "Tcp", src = [local.cidr[k]], dst = [local.cidr[k]], ports = local.k0s_node_tcp_ports },
      { name = "AllowHubNodesUdpIn", priority = 151, direction = "Inbound", access = "Allow", protocol = "Udp", src = [local.cidr[k]], dst = [local.cidr[k]], ports = local.k0s_node_udp_ports },
      { name = "AllowLoadBalancerProbeIn", priority = 160, direction = "Inbound", access = "Allow", protocol = "Tcp", src = ["AzureLoadBalancer"], dst = [local.cidr[k]], ports = [for p in distinct(concat([local.kube_api_port], h.private_ports, h.public_ports)) : tostring(p)] },
      { name = "AllowHubNodesTcpOut", priority = 150, direction = "Outbound", access = "Allow", protocol = "Tcp", src = [local.cidr[k]], dst = [local.cidr[k]], ports = local.k0s_node_tcp_ports },
      { name = "AllowHubNodesUdpOut", priority = 151, direction = "Outbound", access = "Allow", protocol = "Udp", src = [local.cidr[k]], dst = [local.cidr[k]], ports = local.k0s_node_udp_ports },
    ] : r if h.count > 1]
  }

  # Shared tail of every workload NSG.
  deny_tail = [
    { name = "DenyVnetIn", priority = 4000, direction = "Inbound", access = "Deny", protocol = "*", src = ["VirtualNetwork"], dst = ["*"], ports = ["*"] },
    { name = "DenyAllIn", priority = 4096, direction = "Inbound", access = "Deny", protocol = "*", src = ["*"], dst = ["*"], ports = ["*"] },
    { name = "DenyVnetOut", priority = 4000, direction = "Outbound", access = "Deny", protocol = "*", src = ["*"], dst = ["VirtualNetwork"], ports = ["*"] },
  ]

  nsg_rules = {
    dmz = concat([
      { name = "AllowBastionSshKubeIn", priority = 100, direction = "Inbound", access = "Allow", protocol = "Tcp", src = [local.cidr.bastion], dst = [local.cidr.dmz], ports = ["22", "6443"] },
      { name = "AllowSproutsEnvoyPrivateIn", priority = 110, direction = "Inbound", access = "Allow", protocol = "Tcp", src = [local.cidr.tenants], dst = [local.cidr.dmz], ports = [tostring(var.envoy_port)] },
      { name = "AllowRunnerEnvoyIn", priority = 130, direction = "Inbound", access = "Allow", protocol = "Tcp", src = local.runner, dst = [local.cidr.dmz], ports = [tostring(var.envoy_port)] },
      { name = "AllowCoreBusIn", priority = 140, direction = "Inbound", access = "Allow", protocol = "Tcp", src = [local.cidr.core], dst = [local.cidr.dmz], ports = [tostring(var.bus_port)] },
      { name = "AllowFarmerApiOut", priority = 100, direction = "Outbound", access = "Allow", protocol = "Tcp", src = [local.cidr.dmz], dst = [local.cidr.core], ports = [tostring(var.farmer_api_port)] },
      { name = "AllowAccountsStoreOut", priority = 110, direction = "Outbound", access = "Allow", protocol = "Tcp", src = [local.cidr.dmz], dst = [local.cidr.core], ports = [tostring(var.accounts_store_port)] },
    ], local.ha_rules.dmz, local.deny_tail)

    core = concat([
      { name = "AllowBastionSshKubeIn", priority = 100, direction = "Inbound", access = "Allow", protocol = "Tcp", src = [local.cidr.bastion], dst = [local.cidr.core], ports = ["22", "6443"] },
      { name = "AllowDmzFarmerApiIn", priority = 110, direction = "Inbound", access = "Allow", protocol = "Tcp", src = [local.cidr.dmz], dst = [local.cidr.core], ports = [tostring(var.farmer_api_port)] },
      { name = "AllowRunnerHttpsIn", priority = 120, direction = "Inbound", access = "Allow", protocol = "Tcp", src = local.runner, dst = [local.cidr.core], ports = [tostring(var.core_public_port)] },
      { name = "AllowDmzAccountsStoreIn", priority = 130, direction = "Inbound", access = "Allow", protocol = "Tcp", src = [local.cidr.dmz], dst = [local.cidr.core], ports = [tostring(var.accounts_store_port)] },
      { name = "AllowBusOut", priority = 100, direction = "Outbound", access = "Allow", protocol = "Tcp", src = [local.cidr.core], dst = [local.cidr.dmz], ports = [tostring(var.bus_port)] },
    ], local.ha_rules.core, local.deny_tail)

    tenants = concat([
      { name = "AllowBastionAdminIn", priority = 100, direction = "Inbound", access = "Allow", protocol = "Tcp", src = [local.cidr.bastion], dst = [local.cidr.tenants], ports = ["22", "5986"] },
      { name = "AllowEnvoyPrivateOut", priority = 100, direction = "Outbound", access = "Allow", protocol = "Tcp", src = [local.cidr.tenants], dst = [local.cidr.dmz], ports = [tostring(var.envoy_port)] },
      { name = "DenyCorePublicOut", priority = 200, direction = "Outbound", access = "Deny", protocol = "*", src = ["*"], dst = [for ip in local.hub_public_ips.core : "${ip}/32"], ports = ["*"] },
      { name = "DenyDmzPublicOut", priority = 210, direction = "Outbound", access = "Deny", protocol = "*", src = ["*"], dst = [for ip in local.hub_public_ips.dmz : "${ip}/32"], ports = ["*"] },
    ], local.deny_tail)

    # Azure's documented rules for AzureBastionSubnet, with the internet
    # source narrowed to runner_cidr (Azure allows Internet or a list of
    # public addresses there). Outbound to the VMs adds 5986 and 6443 to the
    # documented 22 and 3389 for native client tunnels on those ports.
    bastion = [
      { name = "AllowHttpsInbound", priority = 120, direction = "Inbound", access = "Allow", protocol = "Tcp", src = local.runner, dst = ["*"], ports = ["443"] },
      { name = "AllowGatewayManagerInbound", priority = 130, direction = "Inbound", access = "Allow", protocol = "Tcp", src = ["GatewayManager"], dst = ["*"], ports = ["443"] },
      { name = "AllowAzureLoadBalancerInbound", priority = 140, direction = "Inbound", access = "Allow", protocol = "Tcp", src = ["AzureLoadBalancer"], dst = ["*"], ports = ["443"] },
      { name = "AllowBastionHostCommunication", priority = 150, direction = "Inbound", access = "Allow", protocol = "*", src = ["VirtualNetwork"], dst = ["VirtualNetwork"], ports = ["8080", "5701"] },
      { name = "DenyAllInbound", priority = 4096, direction = "Inbound", access = "Deny", protocol = "*", src = ["*"], dst = ["*"], ports = ["*"] },
      { name = "AllowSshRdpOutbound", priority = 100, direction = "Outbound", access = "Allow", protocol = "*", src = ["*"], dst = ["VirtualNetwork"], ports = ["22", "3389", "5986", "6443"] },
      { name = "AllowAzureCloudOutbound", priority = 110, direction = "Outbound", access = "Allow", protocol = "Tcp", src = ["*"], dst = ["AzureCloud"], ports = ["443"] },
      { name = "AllowBastionCommunication", priority = 120, direction = "Outbound", access = "Allow", protocol = "*", src = ["VirtualNetwork"], dst = ["VirtualNetwork"], ports = ["8080", "5701"] },
      { name = "AllowHttpOutbound", priority = 130, direction = "Outbound", access = "Allow", protocol = "*", src = ["*"], dst = ["Internet"], ports = ["80"] },
      { name = "DenyAllOutbound", priority = 4096, direction = "Outbound", access = "Deny", protocol = "*", src = ["*"], dst = ["*"], ports = ["*"] },
    ]
  }
}

resource "azurerm_network_security_group" "subnet" {
  for_each = local.nsg_rules

  name                = "uat-${each.key}-nsg"
  location            = azurerm_resource_group.run.location
  resource_group_name = azurerm_resource_group.run.name
  tags                = local.tags

  # A service tag ("VirtualNetwork", "GatewayManager", ...) or "*" is only
  # valid in the singular address and port fields, so a one-element list uses
  # the singular field and a longer list the plural one.
  dynamic "security_rule" {
    for_each = each.value
    content {
      name                         = security_rule.value.name
      priority                     = security_rule.value.priority
      direction                    = security_rule.value.direction
      access                       = security_rule.value.access
      protocol                     = security_rule.value.protocol
      source_port_range            = "*"
      source_address_prefix        = length(security_rule.value.src) == 1 ? security_rule.value.src[0] : null
      source_address_prefixes      = length(security_rule.value.src) == 1 ? null : security_rule.value.src
      destination_address_prefix   = length(security_rule.value.dst) == 1 ? security_rule.value.dst[0] : null
      destination_address_prefixes = length(security_rule.value.dst) == 1 ? null : security_rule.value.dst
      destination_port_range       = length(security_rule.value.ports) == 1 ? security_rule.value.ports[0] : null
      destination_port_ranges      = length(security_rule.value.ports) == 1 ? null : security_rule.value.ports
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "workload" {
  for_each = azurerm_subnet.workload

  subnet_id                 = each.value.id
  network_security_group_id = azurerm_network_security_group.subnet[each.key].id
}

# Owner, 2026-10-06: the Bastion fails closed. If Azure refuses this NSG,
# the apply fails; there is no switch to run the Bastion without one.
resource "azurerm_subnet_network_security_group_association" "bastion" {
  subnet_id                 = azurerm_subnet.bastion.id
  network_security_group_id = azurerm_network_security_group.subnet["bastion"].id
}
