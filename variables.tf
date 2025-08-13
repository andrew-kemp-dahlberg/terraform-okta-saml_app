# variables.tf
variable "name" {
  description = "Application label"
  type        = string
}

# variable "admin_note" {
#   type = object({
#     saas_mgmt_name  = string
#     accounting_name = string
#     sso_enforced    = bool
#     service_accounts       = list(string)
#     app_owner              = string
#     last_access_audit_date = string
#     additional_notes       = optional(string)
#   })


# validation {
#   condition     = can(regex("^\\d{4}-\\d{2}-\\d{2}$", var.admin_note.last_access_audit_date)) || var.admin_note.last_access_audit_date == ""
#   error_message = "Last access audit date must be in YYYY-MM-DD format or empty."
# }

# validation {
#   condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.admin_note.app_owner))
#   error_message = "App owner must be a valid email address."
# }

# validation {
#   condition = alltrue([
#     for account in var.admin_note.service_accounts :
#     can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", account))
#   ])
#   error_message = "Service accounts must be valid email addresses."
# }

# validation {
#   condition = var.admin_note.lifecycle.other_automation == null || alltrue([
#     try(contains(["HRIS", "Okta Workflows fully automated", "Okta workflows Zendesk", "AWS", "None"],
#       var.admin_note.lifecycle.other_automation.create.type), false),
#     try(contains(["HRIS", "Okta Workflows fully automated", "Okta workflows Zendesk", "AWS", "None"],
#       var.admin_note.lifecycle.other_automation.update.type), false),
#     try(contains(["HRIS", "Okta Workflows fully automated", "Okta workflows Zendesk", "AWS", "None"],
#       var.admin_note.lifecycle.other_automation.deactivate.type), false)
#   ])
#   error_message = "Alternative Lifecycle automation methods must be one of: HRIS, Okta Workflows fully automated, Okta workflows Zendesk, AWS, None."
# }

# validation {
#   condition = var.admin_note.lifecycle.other_automation == null || alltrue([
#     try(contains(["HRIS", "None"], var.admin_note.lifecycle.other_automation.create.type), false) ||
#     try(can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", var.admin_note.lifecycle.other_automation.create.link)), false) ||
#     try(var.admin_note.lifecycle.other_automation.create.link == "", false),

#     try(contains(["HRIS", "SCIM", "None"], var.admin_note.lifecycle.other_automation.update.type), false) ||
#     try(can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", var.admin_note.lifecycle.other_automation.update.link)), false) ||
#     try(var.admin_note.lifecycle.other_automation.update.link == "", false),

#     try(contains(["HRIS", "SCIM", "None"], var.admin_note.lifecycle.other_automation.deactivate.type), false) ||
#     try(can(regex("^(https?://|www\\.)[^\\s/$.?#].[^\\s]*$", var.admin_note.lifecycle.other_automation.deactivate.link)), false) ||
#     try(var.admin_note.lifecycle.other_automation.deactivate.link == "", false)
#   ])
#   error_message = "Automation links must be valid URLs starting with http://, https://, or www, or empty. Links can be null or empty if type is HRIS, SCIM, or None."
# }
# }

variable "final_schema" {
  description = "Set this variable to false on the initial apply of an app with SCIM to avoid schema errors."
  type        = bool
  default    = true
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
    accessibility_self_service       = optional(bool, null)
    auto_submit_toolbar              = optional(bool, null)
    hide_ios                         = optional(bool, null)
    hide_web                         = optional(bool, null)
    default_relay_state              = optional(string, null)

    // Endpoint settings
    acs_endpoints             = optional(list(string), null)
    single_logout_certificate = optional(string, null)
    single_logout_issuer      = optional(string, null)
    single_logout_url         = optional(string, null)

    // SAML protocol settings
    assertion_signed            = optional(bool, null)
    authn_context_class_ref     = optional(string, null)
    digest_algorithm            = optional(string, null)
    honor_force_authn           = optional(bool, null)
    idp_issuer                  = optional(string, null)
    request_compressed          = optional(bool, null)
    response_signed             = optional(bool, null)
    saml_signed_request_enabled = optional(bool, null)
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
    status              = optional(string, null)
    enduser_note        = optional(string, null)
    implicit_assignment = optional(bool, null)
    app_links           = optional(map(any), null)

    // Attribute statements
    user_attribute_statements = optional(list(object({
      name        = string
      name_format = optional(string, null)
      values      = list(string)
    })), null)
    group_attribute_statements = optional(object({
      name        = string
      name_format = optional(string, null)
    }), null)

    // Custom settings
    custom_settings = optional(map(any), null)
  })
validation {
  condition = var.saml_app == null || (
    var.saml_app.preconfigured_app != null || (
      var.saml_app.sso_url != null &&
      var.saml_app.audience != null &&
      var.saml_app.logo != null
    )
  )
  error_message = "For custom SAML applications (not using preconfigured_app), you must provide sso_url, audience, and logo."
}

validation {
  condition = var.saml_app == null || (
    var.saml_app.saml_version == null ||
    try(contains(["1.1", "2.0"], var.saml_app.saml_version), false)
  )
  error_message = "SAML version must be either '1.1' or '2.0'."
}

validation {
  condition = var.saml_app == null || (
    var.saml_app.user_name_template_push_status == null ||
    try(contains(["PUSH", "DONT_PUSH"], var.saml_app.user_name_template_push_status), false)
  )
  error_message = "user_name_template_push_status must be either 'PUSH' or 'DONT_PUSH'."
}

validation {
  condition = var.saml_app == null || (
    var.saml_app.user_name_template_type == null ||
    try(contains(["NONE", "BUILT_IN", "CUSTOM"], var.saml_app.user_name_template_type), false)
  )
  error_message = "user_name_template_type must be one of: 'NONE', 'BUILT_IN', or 'CUSTOM'."
}

validation {
  condition = var.saml_app == null || (
    var.saml_app.status == null ||
    try(contains(["ACTIVE", "INACTIVE"], var.saml_app.status), false)
  )
  error_message = "Application status must be either 'ACTIVE' or 'INACTIVE'."
}

validation {
  condition = var.saml_app == null || (
    var.saml_app.digest_algorithm == null ||
    try(contains(["SHA1", "SHA256", "SHA512"], var.saml_app.digest_algorithm), false)
  )
  error_message = "Digest algorithm must be one of: 'SHA1', 'SHA256', or 'SHA512'."
}

validation {
  condition = var.saml_app == null || (
    var.saml_app.signature_algorithm == null ||
    try(contains(["RSA_SHA1", "RSA_SHA256", "RSA_SHA512"], var.saml_app.signature_algorithm), false)
  )
  error_message = "Signature algorithm must be one of: 'RSA_SHA1', 'RSA_SHA256', or 'RSA_SHA512'."
}

validation {
  condition = var.saml_app == null || (
    var.saml_app.subject_name_id_format == null ||
    try(contains([
      "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
      "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
      "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
      "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    ], var.saml_app.subject_name_id_format), false) ||
    try(can(regex("^urn:oasis:names:tc:SAML:[1-2]\\.[0-9]:nameid-format:.+$", var.saml_app.subject_name_id_format)), false)
  )
  error_message = "subject_name_id_format must be a valid SAML NameID format URN."
}

validation {
  condition = (
    var.saml_app == null || 
    var.saml_app.key_years_valid == null || 
    try(tonumber(var.saml_app.key_years_valid) >= 2 && tonumber(var.saml_app.key_years_valid) <= 10, false)
  )
  error_message = "When specified, key_years_valid must be between 2 and 10 years."
}

validation {
  condition = (
    var.saml_app == null || 
    try(var.saml_app.key_name == null && var.saml_app.key_years_valid == null, false) || 
    try(var.saml_app.key_name != null && var.saml_app.key_years_valid != null, false)
  )
  error_message = "key_name and key_years_valid must either both be specified or both be omitted."
}

validation {
  condition = var.saml_app == null || (
    var.saml_app.user_attribute_statements == null ? true : try(alltrue([
      for attr in var.saml_app.user_attribute_statements :
      attr.name != null &&
      contains(["basic", "uri reference", "unspecified"], coalesce(attr.name_format, "unspecified")) &&
      length(attr.values) > 0
    ]), false)
  )
  error_message = "Each user_attribute_statements object must have a name, valid name_format, and at least one value."
}
}


variable "authentication_policy" {
  description = "This can equal low, medium, high and these will map to the authentication policy environment variable or can be an id of an auth policy. If it is custom recommendation is to use the module within the same terraform config"
  type        = string
  default     = "high"
}

variable "roles" {
  description = "Creates role-based assignments for groups that can be assigned to users through the SAML application."
  type = list(object({
    name                = string
    attribute_statement = optional(bool, false)
    profile             = optional(map(string),{}) 
  }))

  default = [{
    name                = "assignment"
    profile             = {}
    attribute_statement = false
  }]

  validation {
    condition = length([
      for role in var.roles : role
      if can(regex("^[a-zA-Z0-9_-]+$", role.name))
    ]) == length(var.roles)
    error_message = "Role names must contain only alphanumeric characters, hyphens, and underscores."
  }

  validation {
    condition = length([
      for role in var.roles : role
      if length(role.name) >= 1 && length(role.name) <= 128
    ]) == length(var.roles)
    error_message = "Role names must be between 1 and 128 characters."
  }

  validation {
    condition = alltrue([
      for role in var.roles : can(jsonencode(role.profile))
    ])
    error_message = "All profile objects must be valid JSON."
  }
}


variable "base_schema" {
  description = "Base schema properties for the application"
  type = list(object({
    id          = string
    title       = string
    type        = string
    master      = optional(string, "PROFILE_MASTER")
    permissions = optional(string, "READ_ONLY")
    required    = optional(bool, false)
    user_type   = optional(string, "default")
    pattern     = optional(string, null)
  }))
  
  default = [{
    id          = "userName"
    title       = "Username"
    type        = "string"
    master      = "PROFILE_MASTER"
    permissions = "READ_ONLY"
    required    = true
    user_type   = "default"
    pattern     = null
  }]

  validation {
    condition = alltrue([
      for item in var.base_schema :
      contains(["string", "boolean", "number", "integer", "array", "object"], item.type)
    ])
    error_message = "Base schema type must be one of: string, boolean, number, integer, array, or object."
  }

  validation {
    condition = alltrue([
      for item in var.base_schema :
      item.master == null || contains(["PROFILE_MASTER", "OKTA"], item.master)
    ])
    error_message = "Base schema master must be one of: PROFILE_MASTER or OKTA."
  }

  validation {
    condition = alltrue([
      for item in var.base_schema :
      item.permissions == null || contains(["READ_WRITE", "READ_ONLY", "HIDE"], item.permissions)
    ])
    error_message = "Base schema permissions must be one of: READ_WRITE, READ_ONLY, or HIDE."
  }
}

variable "custom_schema" {
  description = "Custom schema properties for the user"
  type = list(object({
    index              = string
    title              = string
    type               = string
    description        = optional(string, null)
    master             = optional(string, "OKTA")
    permissions        = optional(string, null)
    required           = optional(bool, false)
    scope              = optional(string, null)
    user_type          = optional(string, null)
    array_enum         = optional(list(string), null)
    array_type         = optional(string, null)
    enum               = optional(list(string), null)
    external_name      = optional(string, null)
    external_namespace = optional(string, null)
    max_length         = optional(number, null)
    min_length         = optional(number, null)
    pattern            = optional(string, null)
    union              = optional(bool, false)  # Add this
    unique             = optional(string, "NOT_UNIQUE")
    one_of = optional(list(object({
      const = string
      title = string
    })), null)
    array_one_of = optional(list(object({
      const = string
      title = string
    })), null)
    master_override_priority = optional(list(object({
      type  = optional(string, null)
      value = string
    })), null)
  }))
  default = []


  validation {
    condition = alltrue([
      for item in var.custom_schema :
      contains(["string", "boolean", "number", "integer", "array", "object"], item.type)
    ])
    error_message = "Custom schema type must be one of: string, boolean, number, integer, array, or object."
  }

  validation {
    condition = alltrue([
      for item in var.custom_schema :
      item.master == null || contains(["PROFILE_MASTER", "OKTA"], item.master)
    ])
    error_message = "Custom schema master must be one of: PROFILE_MASTER or OKTA."
  }

  validation {
    condition = alltrue([
      for item in var.custom_schema :
      item.permissions == null || contains(["READ_WRITE", "READ_ONLY", "HIDE"], item.permissions)
    ])
    error_message = "Custom schema permissions must be one of: READ_WRITE, READ_ONLY, or HIDE."
  }

  validation {
    condition = alltrue([
      for item in var.custom_schema :
      item.unique == null || contains(["UNIQUE_VALIDATED", "NOT_UNIQUE"], item.unique)
    ])
    error_message = "Custom schema unique must be either UNIQUE_VALIDATED or NOT_UNIQUE."
  }

  validation {
    condition = alltrue([
      for item in var.custom_schema :
      item.type != "array" || item.array_type != null
    ])
    error_message = "Custom schema array_type must be specified when type is set to array."
  }
}

variable "profile_mappings" {
  description = "Profile mappings between Okta and the application"
  type = object({
    to_app = optional(list(object({
      id          = string
      expression  = string
      push_status = optional(string, "PUSH")
    })), [])
    to_okta = optional(list(object({
      id          = string
      expression  = string
      push_status = optional(string, "PUSH")
    })), [])
  })
  
  default = {
    to_app  = []
    to_okta = []
  }

  validation {
    condition = alltrue([
      for mapping in var.profile_mappings.to_app :
      mapping.push_status == null || contains(["PUSH", "DONT_PUSH"], mapping.push_status)
    ])
    error_message = "Profile mapping push_status must be either 'PUSH' or 'DONT_PUSH'."
  }

  validation {
    condition = alltrue([
      for mapping in var.profile_mappings.to_okta :
      mapping.push_status == null || contains(["PUSH", "DONT_PUSH"], mapping.push_status)
    ])
    error_message = "Profile mapping push_status must be either 'PUSH' or 'DONT_PUSH'."
  }
}