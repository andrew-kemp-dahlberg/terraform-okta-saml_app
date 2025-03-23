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
      high   = optional(string)
      medium = optional(string)
      low    = optional(string)
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
    assertion_signed            = optional(bool, true)
    authn_context_class_ref     = optional(string, "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
    digest_algorithm            = optional(string, "SHA256")
    honor_force_authn           = optional(bool, true)
    idp_issuer                  = optional(string, "http://www.okta.com/$${org.externalKey}")
    request_compressed          = optional(bool, null)
    response_signed             = optional(bool, true)
    saml_signed_request_enabled = optional(bool, false)
    saml_version                = optional(string, "2.0")
    signature_algorithm         = optional(string, "RSA_SHA256")
    sp_issuer                   = optional(string, null)
    subject_name_id_format      = optional(string, "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
    subject_name_id_template    = optional(string, "$${user.userName}")

    // Certificate settings
    key_name        = optional(string, null)
    key_years_valid = optional(number, null)

    // User management settings
    user_name_template             = optional(string, "$${source.login}")
    user_name_template_push_status = optional(string, null)
    user_name_template_suffix      = optional(string, null)
    user_name_template_type        = optional(string, "BUILT_IN")
    inline_hook_id                 = optional(string, null)

    // Application settings
    status              = optional(string, "ACTIVE")
    enduser_note        = optional(string, null)
    implicit_assignment = optional(bool, false)
    app_links_json      = optional(string, null)

    // Attribute statements
    user_attribute_statements = optional(list(object({
      name        = string
      name_format = optional(string, "unspecified")
      values      = list(string)
    })), [])
    group_attribute_statements = optional(object({
      name        = string
      name_format = optional(string, "unspecified")
    }), null)

    // Custom settings
    custom_settings = optional(map(any), null)
  })

  # Validate required fields for non-preconfigured apps
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

  # Validate SAML version
  validation {
    condition = var.saml_app == null || (
      var.saml_app.saml_version == null ||
      contains(["1.1", "2.0"], var.saml_app.saml_version)
    )
    error_message = "SAML version must be either '1.1' or '2.0'."
  }

  # Validate user_name_template_push_status
  validation {
    condition = var.saml_app == null || (
      var.saml_app.user_name_template_push_status == null ||
      contains(["PUSH", "DONT_PUSH"], var.saml_app.user_name_template_push_status)
    )
    error_message = "user_name_template_push_status must be either 'PUSH' or 'DONT_PUSH'."
  }

  # Validate user_name_template_type
  validation {
    condition = var.saml_app == null || (
      var.saml_app.user_name_template_type == null ||
      contains(["NONE", "BUILT_IN", "CUSTOM"], var.saml_app.user_name_template_type)
    )
    error_message = "user_name_template_type must be one of: 'NONE', 'BUILT_IN', or 'CUSTOM'."
  }

  # Validate application status
  validation {
    condition = var.saml_app == null || (
      var.saml_app.status == null ||
      contains(["ACTIVE", "INACTIVE"], var.saml_app.status)
    )
    error_message = "Application status must be either 'ACTIVE' or 'INACTIVE'."
  }

  # Validate digest algorithm
  validation {
    condition = var.saml_app == null || (
      var.saml_app.digest_algorithm == null ||
      contains(["SHA1", "SHA256", "SHA512"], var.saml_app.digest_algorithm)
    )
    error_message = "Digest algorithm must be one of: 'SHA1', 'SHA256', or 'SHA512'."
  }

  # Validate signature algorithm
  validation {
    condition = var.saml_app == null || (
      var.saml_app.signature_algorithm == null ||
      contains(["RSA_SHA1", "RSA_SHA256", "RSA_SHA512"], var.saml_app.signature_algorithm)
    )
    error_message = "Signature algorithm must be one of: 'RSA_SHA1', 'RSA_SHA256', or 'RSA_SHA512'."
  }

  # Validate subject_name_id_format - common formats
  validation {
    condition = var.saml_app == null || (
      var.saml_app.subject_name_id_format == null ||
      contains([
        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
      ], var.saml_app.subject_name_id_format) ||
      can(regex("^urn:oasis:names:tc:SAML:[1-2]\\.[0-9]:nameid-format:.+$", var.saml_app.subject_name_id_format))
    )
    error_message = "subject_name_id_format must be a valid SAML NameID format URN."
  }

  # Validate key_years_valid (if provided)
  validation {
    condition = var.saml_app == null || (
      var.saml_app.key_years_valid == null ||
      (var.saml_app.key_years_valid >= 2 && var.saml_app.key_years_valid <= 10)
    )
    error_message = "key_years_valid must be between 2 and 10 years."
  }

  # Validate that key_name and key_years_valid are set together
  validation {
    condition = var.saml_app == null || (
      (var.saml_app.key_name == null && var.saml_app.key_years_valid == null) ||
      (var.saml_app.key_name != null && var.saml_app.key_years_valid != null)
    )
    error_message = "key_name and key_years_valid must be set together."
  }

  # Validate user attribute statements
  validation {
    condition = var.saml_app == null || (
      var.saml_app.user_attribute_statements == null ? true : alltrue([
        for attr in var.saml_app.user_attribute_statements :
        attr.name != null &&
        contains(["basic", "uri reference", "unspecified"], coalesce(attr.name_format, "unspecified")) &&
        length(attr.values) > 0
      ])
    )
    error_message = "Each user_attribute_statements object must have a name, valid name_format, and at least one value."
  }

  # Validate app_links_json is valid JSON if provided
  validation {
    condition = var.saml_app == null || (
      var.saml_app.app_links_json == null ||
      can(jsondecode(var.saml_app.app_links_json))
    )
    error_message = "app_links_json must be a valid JSON string."
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
    claim               = optional(bool, false)
    profile             = map(string) # Changed from map(any) for better type safety
  }))

  default = [{
    name                = "assignment"
    profile             = {}
    attribute_statement = false
    claim               = false
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
  description = "List of application user base schema properties to configure"
  type = list(object({
    index       = string
    title       = string
    type        = string
    master      = optional(string, "PROFILE_MASTER")
    pattern     = optional(string)
    permissions = optional(string, "READ_ONLY")
    required    = optional(bool, true)
    user_type   = optional(string, "default")
  }))
  default = [{
    index       = "userName"
    master      = "PROFILE_MASTER"
    pattern     = null
    permissions = "READ_ONLY"
    required    = true
    title       = "Username"
    type        = "string"
    user_type   = "default"
  }]

  validation {
    condition = alltrue([
      for prop in var.base_schema :
      contains(["string", "boolean", "number", "integer", "array", "object"], prop.type)
    ])
    error_message = "Type must be one of: string, boolean, number, integer, array, or object."
  }

  validation {
    condition = alltrue([
      for prop in var.base_schema :
      prop.master == null || contains(["PROFILE_MASTER", "OKTA"], prop.master)
    ])
    error_message = "Master must be one of: PROFILE_MASTER or OKTA."
  }

  validation {
    condition = alltrue([
      for prop in var.base_schema :
      prop.permissions == null || contains(["READ_WRITE", "READ_ONLY", "HIDE"], prop.permissions)
    ])
    error_message = "Permissions must be one of: READ_WRITE, READ_ONLY, or HIDE."
  }
}
variable "custom_schema" {
  description = "List of custom schema properties to create for the Okta app"
  type = list(object({
    index              = string
    title              = string
    type               = string
    description        = optional(string)
    master             = optional(string, "OKTA")
    scope              = optional(string, "NONE")
    array_enum         = optional(list(string))
    array_type         = optional(string)
    enum               = optional(list(string))
    external_name      = optional(string)
    external_namespace = optional(string)
    max_length         = optional(number)
    min_length         = optional(number)
    permissions        = optional(string, "READ_ONLY")
    required           = optional(bool, false)
    union              = optional(bool, false)
    unique             = optional(string, "NOT_UNIQUE")
    user_type          = optional(string, "default")
    one_of = optional(list(object({
      const = string
      title = string
    })))
    array_one_of = optional(list(object({
      const = string
      title = string
    })))
  }))
  default = []

  validation {
    condition = alltrue([
      for prop in var.custom_schema :
      contains(["string", "boolean", "number", "integer", "array", "object"], prop.type)
    ])
    error_message = "Property type must be one of: string, boolean, number, integer, array, or object."
  }

  validation {
    condition = alltrue([
      for prop in var.custom_schema :
      prop.master == null || contains(["PROFILE_MASTER", "OKTA"], prop.master)
    ])
    error_message = "Master must be either PROFILE_MASTER or OKTA."
  }

  validation {
    condition = alltrue([
      for prop in var.custom_schema :
      prop.scope == null || contains(["SELF", "NONE"], prop.scope)
    ])
    error_message = "Scope must be either SELF or NONE."
  }

  validation {
    condition = alltrue([
      for prop in var.custom_schema :
      prop.permissions == null || contains(["READ_WRITE", "READ_ONLY", "HIDE"], prop.permissions)
    ])
    error_message = "Permissions must be one of: READ_WRITE, READ_ONLY, or HIDE."
  }

  validation {
    condition = alltrue([
      for prop in var.custom_schema :
      prop.unique == null || contains(["UNIQUE_VALIDATED", "NOT_UNIQUE"], prop.unique)
    ])
    error_message = "Unique must be either UNIQUE_VALIDATED or NOT_UNIQUE."
  }

  validation {
    condition = alltrue([
      for prop in var.custom_schema :
      prop.union == null || prop.scope != "SELF" || prop.union == false
    ])
    error_message = "Union cannot be set to true if scope is set to SELF."
  }

  validation {
    condition = alltrue([
      for prop in var.custom_schema :
      prop.type != "array" || prop.array_type != null
    ])
    error_message = "Array type must be specified when type is set to array."
  }
}





