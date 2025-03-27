output "saml_app" {
  description = "Created SAML application details"
  value = {
    id           = okta_app_saml.saml_app.id
    label        = okta_app_saml.saml_app.label
    status       = okta_app_saml.saml_app.status
    sign_on_mode = okta_app_saml.saml_app.sign_on_mode
    entity_id    = okta_app_saml.saml_app.entity_url
  }
}


output "app_url" {
  description = "URL for the application"
  value       = okta_app_saml.saml_app.embed_url
}

output "app_settings" {
  description = "SAML application settings"
  value = {
    sso_url        = var.saml_app.sso_url
    audience       = var.saml_app.audience
    subject_format = var.saml_app.subject_name_id_format
  }
}

output "admin_note_details" {
  description = "Admin note details for the application"
  value = {
    saas_mgmt_name  = var.admin_note.saas_mgmt_name
    accounting_name = var.admin_note.accounting_name
    sso_enforced    = var.admin_note.sso_enforced
    app_owner       = var.admin_note.app_owner
    lifecycle = {
      provisioning   = var.admin_note.lifecycle_automations.provisioning.type
      user_updates   = var.admin_note.lifecycle_automations.user_updates.type
      deprovisioning = var.admin_note.lifecycle_automations.deprovisioning.type
    }
    last_audit_date = var.admin_note.last_access_audit_date
  }
}

output "app_roles" {
  description = "Application roles configuration"
  value       = var.roles
}
