variable "region" {
  description = "Region of the state resource group and storage account."
  type        = string
  default     = "centralindia"
}

variable "resource_group_name" {
  description = "The persistent resource group. destroy.sh looks the state account up here."
  type        = string
  default     = "imas-uat-state"
}

variable "storage_account_name" {
  description = "State storage account name (globally unique, 3 to 24 lowercase letters and digits). Empty: imasuatstate plus 8 random characters."
  type        = string
  default     = ""

  validation {
    condition     = var.storage_account_name == "" || can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "storage_account_name must be 3 to 24 lowercase letters and digits, or empty."
  }
}

variable "container_name" {
  description = "Blob container for run state. Each run is the blob imas-uat/<run_id>.tfstate."
  type        = string
  default     = "tfstate"
}

variable "state_blob_contributors" {
  description = "Object ids of the principals that read and write run state: the imas-uat-github service principal (az ad sp show --id <AZURE_CLIENT_ID> --query id -o tsv), and anyone else who destroys runs by hand."
  type        = list(string)
  default     = []
}

variable "grant_current_principal" {
  description = "Also give the identity running this bootstrap blob access, so the owner can destroy a run by hand."
  type        = bool
  default     = true
}

variable "state_retention_days" {
  description = "Run state blobs not modified for this many days are deleted (a destroyed run's state is not needed; a kept run is gone long before)."
  type        = number
  default     = 30

  validation {
    condition     = var.state_retention_days >= 8
    error_message = "state_retention_days must be at least 8, longer than the longest keep_hours (168)."
  }
}

variable "lock_state_group" {
  description = "Put a CanNotDelete lock on the state resource group."
  type        = bool
  default     = true
}

variable "monthly_budget" {
  description = "Monthly budget for the whole subscription, in its billing currency. Default 100: about twenty runs of a few dollars plus a kept environment for a day or two (the costs in section 4h are guesses)."
  type        = number
  default     = 100

  validation {
    condition     = var.monthly_budget > 0
    error_message = "monthly_budget must be above 0."
  }
}

variable "budget_email" {
  description = "Where the budget alerts go."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_email))
    error_message = "budget_email must be an email address."
  }
}
