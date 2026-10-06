output "resource_group_name" {
  description = "The persistent resource group."
  value       = azurerm_resource_group.state.name
}

output "storage_account_name" {
  description = "The state storage account. Give it to the workflow (TFSTATE_STORAGE_ACCOUNT) or let destroy.sh look it up."
  value       = azurerm_storage_account.state.name
}

output "container_name" {
  description = "The state container."
  value       = azurerm_storage_container.state.name
}

output "backend_config" {
  description = "-backend-config values for uat/tofu; add key=imas-uat/<run_id>.tfstate per run."
  value = {
    resource_group_name  = azurerm_resource_group.state.name
    storage_account_name = azurerm_storage_account.state.name
    container_name       = azurerm_storage_container.state.name
  }
}

output "budget_id" {
  description = "The subscription budget."
  value       = azurerm_consumption_budget_subscription.uat.id
}
