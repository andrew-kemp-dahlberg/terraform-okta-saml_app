#
## Application Configuration Locals
#

locals {
  # Admin Note Configuration
  admin_note = {
    name  = var.admin_note.saas_mgmt_name
    sso   = var.admin_note.sso_enforced
    owner = var.admin_note.app_owner
    audit = var.admin_note.last_access_audit_date
  }

  # Authentication Policy Resolution
  authentication_policy_id = contains(["low", "medium", "high"], var.authentication_policy) ? 
    var.environment.authentication_policy_ids[var.authentication_policy] : 
    var.authentication_policy

  # SAML Application Settings
  label       = coalesce(var.saml_app.label, var.name)
  recipient   = var.saml_app.preconfigured_app == null ? coalesce(var.saml_app.recipient, var.saml_app.sso_url) : var.saml_app.recipient
  destination = var.saml_app.preconfigured_app == null ? coalesce(var.saml_app.destination, var.saml_app.sso_url) : var.saml_app.destination
}

#
## Attribute Statements Configuration
#

locals {
  # User Attribute Statements
  user_attribute_statements = var.saml_app.user_attribute_statements == null ? [] : [
    for attr in var.saml_app.user_attribute_statements : {
      type      = "EXPRESSION"
      name      = attr.name
      namespace = lookup({
        "basic"         = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        "uri reference" = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        "unspecified"   = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
      }, attr.name_format, "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
      values = attr.values
    }
  ]

  # Group Attribute Statements
  attribute_statement_roles = [
    for role in var.roles : role
    if role.attribute_statement == true
  ]
  
  group_attribute_statements_regex = length(local.attribute_statement_roles) > 0 ? format(
    "^APP-ROLE-%s-(%s)$",
    upper(var.name),
    join("|", [for role in local.attribute_statement_roles : upper(role.name)])
  ) : "^$"

  group_attribute_statements = var.saml_app.group_attribute_statements == null ? [] : [
    {
      type = "GROUP"
      name = var.saml_app.group_attribute_statements.name
      namespace = lookup({
        "basic"         = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        "uri reference" = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        "unspecified"   = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
      }, var.saml_app.group_attribute_statements.name_format, "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
      filterType  = "REGEX"
      filterValue = local.group_attribute_statements_regex
    }
  ]

  # Combined Attribute Statements
  attribute_statements_combined = concat(
    local.user_attribute_statements,
    local.group_attribute_statements
  )
}
resource "okta_app_saml" "saml_app" {
  // Basic app configuration
  label             = local.label
  status            = var.saml_app.status != null ? var.saml_app.status : (var.saml_app.preconfigured_app == null ? "ACTIVE" : null)
  preconfigured_app = var.saml_app.preconfigured_app

  // Visual/UI settings
  logo                = var.saml_app.logo
  admin_note          = jsonencode(local.admin_note)
  enduser_note        = var.saml_app.enduser_note
  hide_ios            = var.saml_app.hide_ios != null ? var.saml_app.hide_ios : (var.saml_app.preconfigured_app == null ? false : null)
  hide_web            = var.saml_app.hide_web != null ? var.saml_app.hide_web : (var.saml_app.preconfigured_app == null ? false : null)
  auto_submit_toolbar = var.saml_app.auto_submit_toolbar != null ? var.saml_app.auto_submit_toolbar : (var.saml_app.preconfigured_app == null ? false : null)

  // Accessibility settings
  accessibility_self_service       = var.saml_app.accessibility_self_service != null ? var.saml_app.accessibility_self_service : (var.saml_app.preconfigured_app == null ? false : null)
  accessibility_error_redirect_url = var.saml_app.accessibility_error_redirect_url
  accessibility_login_redirect_url = var.saml_app.accessibility_login_redirect_url

  // Authentication policy
  authentication_policy = var.authentication_policy
  implicit_assignment   = var.saml_app.implicit_assignment != null ? var.saml_app.implicit_assignment : (var.saml_app.preconfigured_app == null ? false : null)

  // User management settings
  user_name_template             = var.saml_app.user_name_template != null ? var.saml_app.user_name_template : (var.saml_app.preconfigured_app == null ? "${source.login}" : null)
  user_name_template_type        = var.saml_app.user_name_template_type != null ? var.saml_app.user_name_template_type : (var.saml_app.preconfigured_app == null ? "BUILT_IN" : null)
  user_name_template_suffix      = var.saml_app.user_name_template_suffix
  user_name_template_push_status = var.saml_app.user_name_template_push_status

  // SAML protocol settings
  saml_version            = var.saml_app.saml_version != null ? var.saml_app.saml_version : (var.saml_app.preconfigured_app == null ? "2.0" : null)
  assertion_signed        = var.saml_app.assertion_signed != null ? var.saml_app.assertion_signed : (var.saml_app.preconfigured_app == null ? true : null)
  response_signed         = var.saml_app.response_signed != null ? var.saml_app.response_signed : (var.saml_app.preconfigured_app == null ? true : null)
  signature_algorithm     = var.saml_app.signature_algorithm != null ? var.saml_app.signature_algorithm : (var.saml_app.preconfigured_app == null ? "RSA_SHA256" : null)
  digest_algorithm        = var.saml_app.digest_algorithm != null ? var.saml_app.digest_algorithm : (var.saml_app.preconfigured_app == null ? "SHA256" : null)
  honor_force_authn       = var.saml_app.honor_force_authn != null ? var.saml_app.honor_force_authn : (var.saml_app.preconfigured_app == null ? false : null)
  authn_context_class_ref = var.saml_app.authn_context_class_ref != null ? var.saml_app.authn_context_class_ref : (var.saml_app.preconfigured_app == null ? "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" : null)
  idp_issuer              = var.saml_app.idp_issuer != null ? var.saml_app.idp_issuer : (var.saml_app.preconfigured_app == null ? "http://www.okta.com/${org.externalKey}" : null)

  // SAML subject configuration
  subject_name_id_format   = var.saml_app.subject_name_id_format != null ? var.saml_app.subject_name_id_format : (var.saml_app.preconfigured_app == null ? "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" : null)
  subject_name_id_template = var.saml_app.subject_name_id_template != null ? var.saml_app.subject_name_id_template : (var.saml_app.preconfigured_app == null ? "${user.userName}" : null)

  // Endpoint configuration
  acs_endpoints       = var.saml_app.acs_endpoints != null ? var.saml_app.acs_endpoints : (var.saml_app.preconfigured_app == null ? [] : null)
  sso_url             = var.saml_app.sso_url
  destination         = var.saml_app.destination == null && var.saml_app.preconfigured_app == null ? var.saml_app.sso_url : var.saml_app.destination
  recipient           = var.saml_app.recipient == null && var.saml_app.preconfigured_app == null ? var.saml_app.sso_url : var.saml_app.recipient
  audience            = var.saml_app.audience
  default_relay_state = var.saml_app.default_relay_state
  sp_issuer           = var.saml_app.sp_issuer

  // Single logout configuration
  single_logout_url         = var.saml_app.single_logout_url
  single_logout_certificate = var.saml_app.single_logout_certificate
  single_logout_issuer      = var.saml_app.single_logout_issuer

  // Advanced SAML settings
  request_compressed          = var.saml_app.request_compressed
  saml_signed_request_enabled = var.saml_app.saml_signed_request_enabled != null ? var.saml_app.saml_signed_request_enabled : (var.saml_app.preconfigured_app == null ? false : null)
  inline_hook_id              = var.saml_app.inline_hook_id

  // Certificate settings
  key_name        = var.saml_app.key_name
  key_years_valid = var.saml_app.key_years_valid

  // App settings (JSON format)
  app_settings_json = var.saml_app.custom_settings != null ? jsonencode(var.saml_app.custom_settings) : null
  app_links_json    = var.saml_app.app_links != null ? jsonencode(var.saml_app.app_links) : null

  // Attribute statements
  dynamic "attribute_statements" {
    for_each = local.attribute_statements_combined 
    content {
      name      = attribute_statements.value.name
      namespace = attribute_statements.value.namespace
      type      = attribute_statements.value.type

      // Only set these if type is EXPRESSION
      values    = attribute_statements.value.type == "EXPRESSION" ? attribute_statements.value.values : null
      
      // Only set these if type is GROUP
      filter_type  = attribute_statements.value.type == "GROUP" ? attribute_statements.value.filterType : null
      filter_value = attribute_statements.value.type == "GROUP" ? attribute_statements.value.filterValue : null
    }
  }
}

locals {
  find_app_url = "https://${var.environment.org_name}.${var.environment.base_url}/api/v1/apps?includeNonDeleted=false&q=${local.label}"
}

data "http" "saml_app_list" {
  url = local.find_app_url
  method = "GET"
  request_headers = {
    Accept = "application/json"
    Authorization = "SSWS ${var.environment.api_token}"
  }
}

locals {
  saml_app_id = try(jsondecode(data.http.saml_app_list.response_body)[0].id, "none")
  base_schema_url =  "https://${var.environment.org_name}.${var.environment.base_url}/api/v1/meta/schemas/apps/${local.saml_app_id}/default"
}


data "http" "schema" {
  url = local.base_schema_url
  method = "GET"
  request_headers = {
    Accept = "application/json"
    Authorization = "SSWS ${var.environment.api_token}"
  }
}


data "external" "pre-condition" {
  program = ["bash", "-c", <<-EOT
    echo '{"running": "precondition"}'
  EOT
  ]

  lifecycle {
    # Check SAML app list API response
    precondition {
      condition = data.http.saml_app_list.status_code == 200
      error_message = "API request failed with status code: ${data.http.saml_app_list.status_code}. Error: ${data.http.saml_app_list.response_body}"
    }

    # Check SAML app ID
      precondition {
      condition     = local.saml_app_id == "none" || local.saml_app_id == try(okta_app_saml.saml_app.id, "n/a")
      error_message = "An application with label '${local.label}' already exists in Okta outside of Terraform. Either modify the label in your configuration or delete/rename the existing application in Okta."
    }

    # Check schema API response
    precondition {
      condition = data.http.schema.status_code == 200 || local.saml_app_id == "none"
      error_message = "Schema API request failed with status code: ${data.http.schema.status_code}. Error: ${data.http.schema.response_body}"
    }
  }
}




#
## Schema Configuration
#

locals {
  # Schema transformation status check
  default_okta_schema = {
    "id": "#base",
    "type": "object",
    "properties": {
      "userName": {
        "title": "Username",
        "type": "string",
        "required": true,
        "scope": "NONE",
        "maxLength": 100,
        "master": {
          "type": "PROFILE_MASTER"
        }
      }
    },
    "required": [
      "userName"
    ]
  }

  default_username_schema = [{
    id          = "userName"
    title       = "Username"
    type        = "string"
    master      = "PROFILE_MASTER"
    permissions = "READ_ONLY"
    required    = true
    user_type   = "default"
    pattern     = null
  }]

  schema_transformation_status = try(
    jsondecode(data.http.schema.response_body).definitions.base != local.default_okta_schema || 
    var.base_schema == local.default_username_schema ? 
    "transformation complete or no transformation required" : 
    "pre-transformation",
    "pre-transformation"
  )

  # Use base_schema directly - no complex transformation needed
  processed_base_schema = local.schema_transformation_status == "pre-transformation" ? 
    local.default_username_schema : 
    var.base_schema

  # Use custom_schema directly
  processed_custom_schema = var.custom_schema
}

#
## Schema Resources
#

resource "okta_app_user_base_schema_property" "base_schema" {
  for_each = {
    for schema in local.processed_base_schema :
    schema.id => schema
  }

  app_id      = okta_app_saml.saml_app.id
  index       = each.value.id
  title       = each.value.title
  type        = each.value.type
  master      = each.value.master
  pattern     = each.value.pattern
  permissions = each.value.permissions
  required    = each.value.required
  user_type   = each.value.user_type
}

resource "okta_app_user_schema_property" "custom_schema" {
  for_each = {
    for schema in local.processed_custom_schema :
    schema.id => schema
  }

  app_id      = okta_app_saml.saml_app.id
  index       = each.value.id
  title       = each.value.title
  type        = each.value.type
  description = each.value.description
  master      = coalesce(each.value.master, "PROFILE_MASTER")
  scope       = length(var.profile_mappings.to_app) > 0 || length(var.profile_mappings.to_okta) > 0 ? "SELF" : "NONE"

  # Array configurations
  array_enum = each.value.array_enum
  array_type = each.value.array_type
  
  dynamic "array_one_of" {
    for_each = each.value.array_one_of != null ? each.value.array_one_of : []
    content {
      const = array_one_of.value.const
      title = array_one_of.value.title
    }
  }

  # Field constraints
  enum               = each.value.enum
  external_name      = each.value.external_name
  external_namespace = each.value.external_namespace
  max_length         = each.value.max_length
  min_length         = each.value.min_length
  permissions        = coalesce(each.value.permissions, "READ_ONLY")
  required           = each.value.required
  union              = each.value.union
  unique             = coalesce(each.value.unique, "NOT_UNIQUE")
  user_type          = coalesce(each.value.user_type, "default")

  dynamic "one_of" {
    for_each = each.value.one_of != null ? each.value.one_of : []
    content {
      const = one_of.value.const
      title = one_of.value.title
    }
  }
}

#
## Profile Mappings
#

data "okta_user_profile_mapping_source" "user" {}

resource "okta_profile_mapping" "to_app" {
  count = length(var.profile_mappings.to_app) > 0 ? 1 : 0
  
  source_id          = data.okta_user_profile_mapping_source.user.id
  target_id          = okta_app_saml.saml_app.id
  delete_when_absent = var.environment.profile_mapping_settings.delete_when_absent
  always_apply       = var.environment.profile_mapping_settings.always_apply

  dynamic "mappings" {
    for_each = var.profile_mappings.to_app
    content {
      id          = mappings.value.id
      expression  = mappings.value.expression
      push_status = mappings.value.push_status
    }
  }
}

resource "okta_profile_mapping" "to_okta" {
  count = length(var.profile_mappings.to_okta) > 0 ? 1 : 0
  
  source_id          = okta_app_saml.saml_app.id
  target_id          = data.okta_user_profile_mapping_source.user.id
  delete_when_absent = var.environment.profile_mapping_settings.delete_when_absent
  always_apply       = var.environment.profile_mapping_settings.always_apply

  dynamic "mappings" {
    for_each = var.profile_mappings.to_okta
    content {
      id          = mappings.value.id
      expression  = mappings.value.expression
      push_status = mappings.value.push_status
    }
  }
}

#
## Group Assignments
#

locals {
  # Group Configuration
  group_configs = [
    for idx, role in var.roles : {
      index       = idx
      role        = role
      profile_str = length(role.profile) == 0 ? "No profile assigned" : replace(jsonencode(role.profile), "/^{|}$/", "")
      note        = format(
        "Assigns the user to the %s with the following profile.\n%s\nGroup is managed by Terraform. Do not edit manually.",
        var.name,
        jsonencode(role.profile)
      )
    }
  ]

  # Custom attributes for groups
  custom_attributes = [
    for config in local.group_configs : merge(
      { 
        notes                  = config.note,
        assignmentProfile      = config.profile_str,
        applicationAssignments = ["Not a department group"],
        mailingLists          = ["Not a department group"],
        pushGroups            = ["Not a department group"]
      }
    )
  ]
}

resource "okta_group" "assignment_groups" {
  count                     = length(var.roles)
  name                      = "APP-ROLE-${upper(var.name)}-${upper(var.roles[count.index].name)}"
  description               = "Group assigns users to ${var.name} with the role of ${var.roles[count.index].name}"
  custom_profile_attributes = jsonencode(local.custom_attributes[count.index])
}



resource "okta_app_group_assignments" "app_groups" {
  app_id = okta_app_saml.saml_app.id

  dynamic "group" {
    for_each = okta_group.assignment_groups
    iterator = grp
    content {
      id       = grp.value.id
      profile  = local.schema_transformation_status == "transformation complete or no transformation required" ? 
                 jsonencode(var.roles[grp.key].profile) : 
                 jsonencode({})
      priority = grp.key + 1
    }
  }
}