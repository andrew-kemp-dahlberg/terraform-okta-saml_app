# variables.tf
variable "client_id" {
  description = "Okta Client ID"
  type        = string
  sensitive   = true
}

variable "org_name" {
  description = "Okta org name ie. company"
  type        = string
}

variable "base_url" {
  description = "Okta Base URL ie. okta.com"
  type        = string
}

variable "private_key_id" {
  description = "Okta Oauth private key id"
  type        = string
  sensitive   = true
}

variable "private_key" {
  description = "Okta Oauth private key"
  type        = string
  sensitive   = true
}

variable "name" {
  description = "Application label"
  type        = string
}

variable "logo" {
  description = "Logo URL"
  type        = string
  default     = null
}


variable "sso_url" {
  description = "SSO URL"
  type        = string
}

variable "audience" {
  description = "Audience URI"
  type        = string
}
variable "recipient" {
  description = "Recipient URL"
  type        = string
  default     = null
}
variable "destination" {
  description = "Destination URL"
  type        = string
  default     = null
}

variable "accessibility_error_redirect_url" {
  description = "Custom error page URL"
  type        = string
  default     = null
}

variable "accessibility_login_redirect_url" {
  description = "Custom login redirect URL"
  type        = string
  default     = null
}

variable "accessibility_self_service" {
  description = "Enable self-service"
  type        = bool
  default     = false
}

variable "acs_endpoints" {
  description = "List of ACS endpoints"
  type        = list(string)
  default     = []
}

variable "admin_note" {
  type = object({
    saas_mgmt_name  = string
    accounting_name = string
    sso_enforced    = bool
    lifecycle_automations = object({
      provisioning = object({
        type = string
        link = string
      })
      user_updates = object({
        type = string
        link = string
      })
      deprovisioning = object({
        type = string
        link = string
      })
    })
    service_accounts       = list(string)
    app_owner              = string
    last_access_audit_date = string
    additional_notes       = string
  })

  validation {
    condition = alltrue([
      contains(["SCIM", "ADP", "Okta Workflows fully automated", "Okta workflows Zendesk", "AWS", "None"],
      var.admin_note.lifecycle_automations.provisioning.type),
      contains(["SCIM", "ADP", "Okta Workflows fully automated", "Okta workflows Zendesk", "AWS", "None"],
      var.admin_note.lifecycle_automations.user_updates.type),
      contains(["SCIM", "ADP", "Okta Workflows fully automated", "Okta workflows Zendesk", "AWS", "None"],
      var.admin_note.lifecycle_automations.deprovisioning.type)
    ])
    error_message = "Lifecycle automation methods must be one of: SCIM, ADP, Okta Workflows fully automated, Okta workflows Zendesk, AWS, None."
  }

  validation {
    condition = alltrue([
      can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", var.admin_note.lifecycle_automations.provisioning.link)) || var.admin_note.lifecycle_automations.provisioning.link == "",
      can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", var.admin_note.lifecycle_automations.user_updates.link)) || var.admin_note.lifecycle_automations.user_updates.link == "",
      can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", var.admin_note.lifecycle_automations.deprovisioning.link)) || var.admin_note.lifecycle_automations.deprovisioning.link == ""
    ])
    error_message = "Automation links must be valid URLs starting with http://, https://, or www, or empty."
  }

  validation {
    condition     = can(regex("^\\d{4}-\\d{2}-\\d{2}$", var.admin_note.last_access_audit_date)) || var.admin_note.last_access_audit_date == ""
    error_message = "Last access audit date must be in YYYY-MM-DD format or empty."
  }

  validation {
    condition = alltrue([
      for link in var.admin_note.automation_links :
      can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", link))
    ])
    error_message = "Automation links must be valid URLs starting with http://, https://, or www."
  }

  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.admin_note.app_owner))
    error_message = "App owner must be a valid email address."
  }

  validation {
    condition = alltrue([
      for account in var.admin_note.service_accounts :
      can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", account))
    ])
    error_message = "Service accounts must be valid email addresses."
  }
}

variable "assertion_signed" {
  description = "Whether SAML assertions are signed"
  type        = bool
  default     = true
}

variable "authn_context_class_ref" {
  description = "Authentication context class reference"
  type        = string
  default     = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
}

variable "auto_submit_toolbar" {
  description = "Display auto-submit toolbar"
  type        = bool
  default     = false
}

variable "default_relay_state" {
  description = "Default relay state"
  type        = string
  default     = null
}

variable "digest_algorithm" {
  description = "Digest algorithm"
  type        = string
  default     = "SHA256"
}

variable "enduser_note" {
  description = "End user notes"
  type        = string
  default     = null
}

variable "hide_ios" {
  description = "Hide on iOS"
  type        = bool
  default     = false
}

variable "hide_web" {
  description = "Hide on web"
  type        = bool
  default     = false
}

variable "honor_force_authn" {
  description = "Honor ForceAuthn"
  type        = bool
  default     = true
}

variable "idp_issuer" {
  description = "IdP issuer URL"
  type        = string
  default     = "http://www.okta.com/$${org.externalKey}"
}

variable "implicit_assignment" {
  description = "Implicit assignment"
  type        = bool
  default     = false
}

variable "inline_hook_id" {
  description = "Inline hook ID"
  type        = string
  default     = null
}

variable "key_name" {
  description = "Key name"
  type        = string
  default     = null
}

variable "key_years_valid" {
  description = "Key validity years"
  type        = number
  default     = null
}

variable "preconfigured_app" {
  description = "Preconfigured application ID"
  type        = string
  default     = null
}



variable "request_compressed" {
  description = "Request compressed"
  type        = bool
  default     = null
}

variable "response_signed" {
  description = "Response signed"
  type        = bool
  default     = true
}

variable "saml_signed_request_enabled" {
  description = "SAML signed request enabled"
  type        = bool
  default     = false
}

variable "saml_version" {
  description = "SAML version"
  type        = string
  default     = "2.0"
}

variable "signature_algorithm" {
  description = "Signature algorithm"
  type        = string
  default     = "RSA_SHA256"
}

variable "single_logout_certificate" {
  description = "Single logout certificate"
  type        = string
  default     = null
}

variable "single_logout_issuer" {
  description = "Single logout issuer"
  type        = string
  default     = null
}

variable "single_logout_url" {
  description = "Single logout URL"
  type        = string
  default     = null
}

variable "sp_issuer" {
  description = "SP issuer"
  type        = string
  default     = null
}

variable "status" {
  description = "Application status"
  type        = string
  default     = "ACTIVE"
}

variable "subject_name_id_format" {
  description = "Subject name ID format"
  type        = string
  default     = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
}

variable "subject_name_id_template" {
  description = "Subject name ID template"
  type        = string
  default     = "$${user.userName}"
}

variable "user_name_template" {
  description = "Username template"
  type        = string
  default     = "$${source.login}"
}

variable "user_name_template_push_status" {
  description = "Username template push status"
  type        = string
  default     = null
}

variable "user_name_template_suffix" {
  description = "Username template suffix"
  type        = string
  default     = null
}

variable "user_name_template_type" {
  description = "Username template type"
  type        = string
  default     = "BUILT_IN"
}

variable "attribute_statements" {
  description = "List of Objects containing, type (user or group), name, formation, filter_value for group attributes that is a regex, "
  type = list(object({
    type         = string
    name         = string
    name_format  = optional(string, "unspecified")
    filter_value = optional(string, null)
    values       = optional(list(string), [])
  }))
  default = null

  validation {
    condition = var.attribute_statements == null ? true : alltrue([
      for attr in var.attribute_statements :
      (attr.type == "user" && attr.values != null && length(attr.values) > 0 && attr.filter_value == null) ||
      (attr.type == "group" && attr.filter_value != null && (attr.values == null || length(attr.values) == 0))
    ])
    error_message = <<EOT
Invalid configuration:
- attribute_statements with "user" types must have non-empty "values" and no filter_value
- attribute_statements with "group"types must have "filter_value" and no "values"
EOT
  }

  validation {
    condition = var.attribute_statements == null ? true : alltrue([
      for attr in var.attribute_statements :
      contains(["user", "group"], attr.type) &&
      contains(["basic", "uri reference", "unspecified"], attr.name_format)
    ])
    error_message = <<EOT
Validation errors:
- Each object in attribute_statements Type must be 'user' or 'group'
- attribute_statements name_format must be 'basic', 'uri reference', or 'unspecified'
EOT
  }

}

variable "authentication_policy_rules" {
  type = list(object({
    name                        = string
    access                      = optional(string, "ALLOW")
    factor_mode                 = optional(string, "2FA")
    type                        = optional(string, "ASSURANCE")
    status                      = optional(string, "ACTIVE")
    re_authentication_frequency = optional(string, "PT43800H")
    custom_expression           = optional(string, null)
    network_includes            = optional(list(string), null)
    network_excludes            = optional(list(string), null)
    risk_score                  = optional(string, "")
    inactivity_period           = optional(string, "")
    network_connection          = optional(string, "ANYWHERE")
    device_is_managed           = optional(bool, null)
    device_is_registered        = optional(bool, null)
    device_assurances_included  = optional(list(string), [])
    groups_included             = optional(list(string), [])
    groups_excluded             = optional(list(string), [])
    users_included              = optional(list(string), [])
    users_excluded              = optional(list(string), [])
    user_types_included         = optional(list(string), [])
    user_types_excluded         = optional(list(string), [])
    constraints                 = optional(list(string), [])
    platform_include = optional(list(object({
      os_type = optional(string, "OTHER")
      type    = optional(string, "DESKTOP")
    })), [])
  }))
  default = null
}

variable "roles" {
  description = "Creates assignments based on groups that can then be assigned to users."
  type = list(object({
    role    = string
    profile = map(any)
  }))
  default = [{
    role    = "assignment"
    profile = {}
  }]
}

variable "admin_role" {
  description = "Creates the role specifically for super admin. Just enter the map for the assignment for the assignment"
  type        = map(any)
  default     = {}
}

variable "device_assurance_policy_ids" {
  description = "Device assurance policies for Mac, iOS, Windows and Android"
  type = object({
    Mac     = optional(string)
    Windows = optional(string)
    iOS     = optional(string)
    Android = optional(string)
  })
  default = {}
}




