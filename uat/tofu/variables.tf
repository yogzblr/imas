# Inputs from the Shared contract in section 4h.

variable "run_id" {
  description = "Run identifier: 6 to 10 lowercase letters and digits. Names the resource group imas-uat-<run_id> and the DNS labels."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{6,10}$", var.run_id))
    error_message = "run_id must be 6 to 10 lowercase letters and digits."
  }
}

variable "release_tag" {
  description = "Release under test, vX.Y.Z or vX.Y.Z-rc.N. Only recorded as a tag here; the hub and enrolment briefs install from it."
  type        = string

  validation {
    condition     = can(regex("^v[0-9]+\\.[0-9]+\\.[0-9]+(-rc\\.[0-9]+)?$", var.release_tag))
    error_message = "release_tag must look like v1.2.3 or v1.2.3-rc.4."
  }
}

variable "region" {
  description = "Azure region. The owner confirms the sizes and quotas there."
  type        = string
  default     = "centralindia"
}

variable "runner_cidr" {
  description = "The one /32 allowed in from the internet: Envoy on the DMZ, 443 on core and 443 on the Bastion."
  type        = string

  validation {
    condition = (
      can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$", var.runner_cidr)) &&
      can(cidrhost(var.runner_cidr, 0)) &&
      var.runner_cidr != "0.0.0.0/32"
    )
    error_message = "runner_cidr must be a single IPv4 address as a /32, for example 203.0.113.7/32."
  }
}

variable "keep_hours" {
  description = "0 (default): the workflow destroys at the end. Above 0: the final destroy is skipped and expires_at is pushed out by this many hours for the janitor."
  type        = number
  default     = 0

  validation {
    condition     = var.keep_hours >= 0 && var.keep_hours <= 168
    error_message = "keep_hours must be between 0 and 168 (one week)."
  }
}

variable "run_budget_hours" {
  description = "How long a run may take before the janitor may delete it, before keep_hours is added. expires_at = time of the first apply + run_budget_hours + keep_hours."
  type        = number
  default     = 4

  validation {
    condition     = var.run_budget_hours >= 1 && var.run_budget_hours <= 24
    error_message = "run_budget_hours must be between 1 and 24."
  }
}

# Sizes (Shared contract).

variable "dmz_size" {
  description = "VM size of uat-dmz."
  type        = string
  default     = "Standard_D2s_v5"
}

variable "core_size" {
  description = "VM size of uat-core."
  type        = string
  default     = "Standard_D8s_v5"
}

variable "linux_sprout_size" {
  description = "VM size of the four Linux sprouts."
  type        = string
  default     = "Standard_B2ls_v2"
}

variable "windows_sprout_size" {
  description = "VM size of the two Windows sprouts."
  type        = string
  default     = "Standard_B2ls_v2"
}

variable "dmz_os_disk_gb" {
  description = "OS disk of uat-dmz, Standard SSD."
  type        = number
  default     = 64
}

variable "core_os_disk_gb" {
  description = "OS disk of uat-core, Standard SSD."
  type        = number
  default     = 128
}

variable "sprout_os_disk_gb" {
  description = "OS disk of every sprout, Standard SSD. 30 GB is the size of the Ubuntu and Windows smalldisk images; it cannot be smaller than the image."
  type        = number
  default     = 30
}

# Image URNs, publisher:offer:sku:version. The owner verifies them with
# az vm image list (agents cannot reach Azure).

variable "ubuntu_image" {
  description = "Ubuntu 24.04 URN, used by both hubs and the Ubuntu sprouts."
  type        = string
  default     = "Canonical:ubuntu-24_04-lts:server:latest"

  validation {
    condition     = length(split(":", var.ubuntu_image)) == 4
    error_message = "ubuntu_image must be publisher:offer:sku:version."
  }
}

variable "alma_image" {
  description = "AlmaLinux 9 URN. A marketplace image: its terms are accepted once per subscription (section 4h prerequisites)."
  type        = string
  default     = "almalinux:almalinux-x86_64:9-gen2:latest"

  validation {
    condition     = length(split(":", var.alma_image)) == 4
    error_message = "alma_image must be publisher:offer:sku:version."
  }
}

variable "alma_image_has_plan" {
  description = "Send a purchase plan (publisher, offer as product, sku as name) with the AlmaLinux image. False by default: Azure refuses almalinux:almalinux-x86_64:9-gen2 with a plan (\"doesn't require plan information\", found by the first Azure run on 2026-10-10). Set true only for an image that has one."
  type        = bool
  default     = false
}

variable "windows_image" {
  description = "Windows Server 2022 Core smalldisk URN."
  type        = string
  default     = "MicrosoftWindowsServer:WindowsServer:2022-datacenter-core-smalldisk-g2:latest"

  validation {
    condition     = length(split(":", var.windows_image)) == 4
    error_message = "windows_image must be publisher:offer:sku:version."
  }
}

variable "admin_user" {
  description = "Admin user on every VM (SSH key on Linux, random password on Windows)."
  type        = string
  default     = "imasuat"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,19}$", var.admin_user)) && !contains(["admin", "administrator", "root", "user", "guest"], var.admin_user)
    error_message = "admin_user must be 3 to 20 lowercase letters and digits, start with a letter, and not be a name Azure reserves."
  }
}

# Ports, from deploy/helm/nats/README.md (Network diagram, NetworkPolicy) and
# deploy/helm/farmer/README.md (NetworkPolicy). They are variables only so the
# NSGs can follow if UAT.2 exposes a service on another host port; keep them
# equal to what the hubs actually listen on.

variable "envoy_port" {
  description = "Envoy's external port on the DMZ host. Owner's decision (2026-10-06): 8443, as a NodePort (production puts Envoy behind an app gateway). Every Envoy rule follows it."
  type        = number
  default     = 8443
}

variable "farmer_api_port" {
  description = "farmer's API on the core host, Envoy's upstream (farmer chart farmer.apiPort; nats chart envoy.upstreams.farmerAPI.port and recipeService.port). The owner: farmer's port can be anything; set it to what the core hub exposes."
  type        = number
  default     = 5405
}

variable "bus_port" {
  description = "The farmerbus node port farmer and saasapi dial on the DMZ host. Owner, 2026-10-06: farmer and saasapi connect to farmerbus, and the bus is exposed as node port 8442 (option (b) of UAT.2 #130) so the DMZ node port range is 8442-8443 only. Behind it is the bus client port (nats chart bus.ports.client, 5406), not the websocket port 5407."
  type        = number
  default     = 8442
}

variable "core_public_port" {
  description = "saasapi and Keycloak on the core host, from the runner only (Shared contract)."
  type        = number
  default     = 443
}

variable "private_dns_zone" {
  description = "Azure Private DNS zone linked to the VNet. Owner, 2026-10-06: sprouts reach Envoy on the DMZ private IP through a private DNS name; the zone holds dmz.<zone> and core.<zone> (A records to the hubs' private IPs). Resolves only inside the VNet."
  type        = string
  default     = "uat.imas.internal"

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$", var.private_dns_zone))
    error_message = "private_dns_zone must be a lowercase DNS name with at least two labels."
  }
}
