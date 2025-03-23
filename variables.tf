# variables.tf
variable "environment" {
  description = "Information to authenticate with Okta Provider"
  type = object({
    org_name       = string
    base_url       = string
    client_id      = string
    private_key_id = string
    private_key    = string
    authentication_policy_ids = object({
      high = optional(string)
      medium = optional(string)
      low = optional(string)
    })
    device_assurance_policy_ids = object({
      Mac     = optional(string)
      Windows = optional(string)
      iOS     = optional(string)
      Android = optional(string)
    })
  })
  sensitive = true

}

variable "name" {
  description = "Application label"
  type        = string
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
      contains(["SCIM", "HRIS", "Okta Workflows fully automated", "Okta workflows Zendesk", "AWS", "None"],
      var.admin_note.lifecycle_automations.provisioning.type),
      contains(["SCIM", "HRIS", "Okta Workflows fully automated", "Okta workflows Zendesk", "AWS", "None"],
      var.admin_note.lifecycle_automations.user_updates.type),
      contains(["SCIM", "HRIS", "Okta Workflows fully automated", "Okta workflows Zendesk", "AWS", "None"],
      var.admin_note.lifecycle_automations.deprovisioning.type)
    ])
    error_message = "Lifecycle automation methods must be one of: SCIM, HRIS, Okta Workflows fully automated, Okta workflows Zendesk, AWS, None."
  }

  validation {
    condition = alltrue([
      (contains(["HRIS", "SCIM", "None"], var.admin_note.lifecycle_automations.provisioning.type)) ||
      can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", var.admin_note.lifecycle_automations.provisioning.link)) ||
      var.admin_note.lifecycle_automations.provisioning.link == "",

      (contains(["HRIS", "SCIM", "None"], var.admin_note.lifecycle_automations.user_updates.type)) ||
      can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", var.admin_note.lifecycle_automations.user_updates.link)) ||
      var.admin_note.lifecycle_automations.user_updates.link == "",

      (contains(["HRIS", "SCIM", "None"], var.admin_note.lifecycle_automations.deprovisioning.type)) ||
      can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", var.admin_note.lifecycle_automations.deprovisioning.link)) ||
      var.admin_note.lifecycle_automations.deprovisioning.link == ""
    ])
    error_message = "Automation links must be valid URLs starting with http://, https://, or www, or empty. Links can be null or empty if type is HRIS, SCIM, or None."
  }

  validation {
    condition     = can(regex("^\\d{4}-\\d{2}-\\d{2}$", var.admin_note.last_access_audit_date)) || var.admin_note.last_access_audit_date == ""
    error_message = "Last access audit date must be in YYYY-MM-DD format or empty."
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

variable "saml_app" {
  description = "Variable for SAML application configuration objects"
  default     = null
  type = object({
    // Required basic settings
    sso_url           = optional(string, null)
    audience          = optional(string, null)
    logo              = optional(string, null)
    label             = optional(string, null)
    preconfigured_app = optional(string, null)

    // Optional basic settings
    recipient   = optional(string, null)
    destination = optional(string, null)

    // Accessibility settings
    accessibility_error_redirect_url = optional(string, null)
    accessibility_login_redirect_url = optional(string, null)
    accessibility_self_service       = optional(bool, false)
    auto_submit_toolbar              = optional(bool, false)
    hide_ios                         = optional(bool, false)
    hide_web                         = optional(bool, false)
    default_relay_state              = optional(string, null)

    // Endpoint settings
    acs_endpoints             = optional(list(string), [])
    single_logout_certificate = optional(string, null)
    single_logout_issuer      = optional(string, null)
    single_logout_url         = optional(string, null)

    // SAML protocol settings
    assertion_signed            = optional(bool, false)
    authn_context_class_ref     = optional(string, null)
    digest_algorithm            = optional(string, null)
    honor_force_authn           = optional(bool, false)
    idp_issuer                  = optional(string, null)
    request_compressed          = optional(bool, null)
    response_signed             = optional(bool, false)
    saml_signed_request_enabled = optional(bool, false)
    saml_version                = optional(string, null)
    signature_algorithm         = optional(string, null)
    sp_issuer                   = optional(string, null)
    subject_name_id_format      = optional(string, null)
    subject_name_id_template    = optional(string, null)

    // Certificate settings
    key_name        = optional(string, null)
    key_years_valid = optional(number, null)

    // User management settings
    user_name_template             = optional(string, null)
    user_name_template_push_status = optional(string, null)
    user_name_template_suffix      = optional(string, null)
    user_name_template_type        = optional(string, null)
    inline_hook_id                 = optional(string, null)

    // Application settings
    status              = optional(string, "ACTIVE")
    enduser_note        = optional(string, null)
    implicit_assignment = optional(bool, false)

    // Attribute statements
    user_attribute_statements = optional(list(object({
      name        = string
      name_format = optional(string, "unspecified")
      values      = list(string)
    })), [])
    group_attribute_statements = optional(object({
      name = string
      name_format = optional(string, "unspecified")
    }), null)

    // Custom settings
    custom_settings = optional(map(any), null)
  })
  validation {
    condition     = var.saml_app != null ? (var.saml_app.preconfigured_app != null || var.saml_app.sso_url != null && var.saml_app.audience != null) : true
    error_message = "SSO URL, and Audience are required fields for SAML applications if it is not a preconfigured app."
  }

  validation {
    condition     = var.saml_app != null ? (var.saml_app.preconfigured_app != null || var.saml_app.logo != null) : true
    error_message = "Either preconfigured_app or logo must be provided for the SAML application."
  }

  validation {
    condition = var.saml_app != null ? (
      var.saml_app.user_attribute_statements == null ? true : alltrue([
        for attr in var.saml_app.user_attribute_statements :
        attr.name != null &&
        contains(["basic", "uri reference", "unspecified"],
        coalesce(attr.name_format, "unspecified"))
      ])
    ) : true
    error_message = "Each user_attribute_statements object must have a name and name_format must be one of: 'basic', 'uri reference', or 'unspecified'."
  }

  validation {
    condition = var.saml_app != null ? (
      var.saml_app.status == null ? true : contains(["ACTIVE", "INACTIVE"], var.saml_app.status)
    ) : true
    error_message = "Application status must be either 'ACTIVE' or 'INACTIVE'."
  }

  validation {
    condition = var.saml_app != null ? (
      var.saml_app.digest_algorithm == null ? true : contains(["SHA1", "SHA256", "SHA512"], var.saml_app.digest_algorithm)
    ) : true
    error_message = "Digest algorithm must be one of: 'SHA1', 'SHA256', or 'SHA512'."
  }

  validation {
    condition = var.saml_app != null ? (
      var.saml_app.signature_algorithm == null ? true : contains(["RSA_SHA1", "RSA_SHA256", "RSA_SHA512"], var.saml_app.signature_algorithm)
    ) : true
    error_message = "Signature algorithm must be one of: 'RSA_SHA1', 'RSA_SHA256', or 'RSA_SHA512'."
  }

}

variable authentication_policy {
  description = "This can equal low, medium, high and these will map to the authentication policy environment variable or can be an id of an auth policy. If it is custom recommendation is to use the module within the same terraform config"
  type = string
  default = "high"
}

variable "roles" {
  description = "Creates assignments based on groups that can then be assigned to users."
  type = list(object({
    name                = string
    attribute_statement = optional(bool, false)
    claim               = optional(bool, false)
    profile             = map(any)
  }))
  default = [{
    name                = "assignment"
    profile             = {}
    attribute_statement = false
    claim               = false
  }]
}

variable "admin_role" {
  description = "Creates the role specifically for super admin. Just enter the map for the assignment for the assignment"
  type = object({
    attribute_statement = optional(bool, false)
    claim               = optional(bool, false)
    profile             = map(any)
  })
  default = {
    profile             = {}
    attribute_statement = false
    claim               = false
  }
}





