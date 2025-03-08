terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.15.0"
    }
  }
}

provider "okta" {
  org_name       = var.environment.org_name
  base_url       = var.environment.base_url
  client_id      = var.environment.client_id
  private_key_id = var.environment.private_key_id
  private_key    = var.environment.private_key
  scopes         = ["okta.apps.manage", "okta.apps.read", "okta.groups.manage", "okta.groups.read", "okta.policies.manage", "okta.policies.read", "okta.profileMappings.manage", "okta.profileMappings.read"]
}
