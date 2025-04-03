locals {
  profile             = [for role in var.roles : role.profile]
  app_group_names     = ["Not a department group"]
  push_group_names    = ["Not a department group"]
  mailing_group_names = ["Not a department group"]
  group_profile = [for p in local.profile : length(p) == 0 ?
    "No profile assigned" :
    replace(
      jsonencode(p),
      "/^{|}$/",
      ""
    )
  ]

  group_notes = [for p in local.profile : format(
    "Assigns the user to the %s with the following profile.\n%s\nGroup is managed by Terraform. Do not edit manually.",
    var.name,
    jsonencode(p)
  )]

  custom_attributes = [for index in range(length(var.roles)) : merge(
    { notes = local.group_notes[index] },
    { assignmentProfile = local.group_profile[index] },
    local.app_group_names != "" ? { applicationAssignments = local.app_group_names } : {},
    local.mailing_group_names != "" ? { mailingLists = local.mailing_group_names } : {},
    local.push_group_names != "" ? { pushGroups = local.push_group_names } : {}
  )]

}

resource "okta_group" "assignment_groups" {
  count                     = length(var.roles)
  name                      = "APP-ROLE-${upper(var.name)}-${upper(var.roles[count.index].name)}"
  description               = "Group assigns users to ${var.name} with the role of ${var.roles[count.index].name}"
  custom_profile_attributes = jsonencode(local.custom_attributes[count.index])
}


locals {
  // Condensed Admin Note         
  admin_note = {
    name = var.admin_note.saas_mgmt_name
    sso  = var.admin_note.sso_enforced
    # auto = distinct([
    #   var.admin_note.lifecycle_automations.provisioning.type,
    #   var.admin_note.lifecycle_automations.user_updates.type,
    #   var.admin_note.lifecycle_automations.deprovisioning.type
    # ])
    owner = var.admin_note.app_owner
    audit = var.admin_note.last_access_audit_date
  }
  // Authentication policy
  authentication_policy_id = contains(["low", "medium", "high"], var.authentication_policy) ? var.environment.authentication_policy_ids[var.authentication_policy] : var.authentication_policy

  // Basic App Settings to get right. 
  saml_label  = var.saml_app.label == null ? var.name : var.saml_app.label
  recipient   = var.saml_app.recipient == null && var.saml_app.preconfigured_app == null ? var.saml_app.sso_url : var.saml_app.recipient
  destination = var.saml_app.destination == null && var.saml_app.preconfigured_app == null ? var.saml_app.sso_url : var.saml_app.destination
  app_links_json = var.saml_app.app_links != null ? jsonencode(var.saml_app.app_links) : null


  //Formatting user attribute statements from saml_app variable
  user_attribute_statements = var.saml_app.user_attribute_statements == null ? null : [
    for attr in var.saml_app.user_attribute_statements : {
      type = "EXPRESSION"
      name = attr.name
      namespace = lookup({
        "basic"         = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        "uri reference" = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        "unspecified"   = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
      }, attr.name_format, "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
      values = attr.values
    }
  ]

  attribute_statement_roles = [
    for role in var.roles : role
    if role.attribute_statement == true
  ]
  group_attribute_statements_regex = length(local.attribute_statement_roles) > 0 ? format(
    "^APP-ROLE-%s-(%s)$",
    upper(var.name),
    join("|", [for role in local.attribute_statement_roles : upper(role.name)])
  ) : "^$"

  group_attribute_statements = var.saml_app.group_attribute_statements != null ? [
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
  ] : null

  // Combine user and group attribute statements with custom_settings var to be pushed through settings
  attribute_statements_combined = concat(
      var.saml_app.user_attribute_statements != null ? local.user_attribute_statements : [],
      var.saml_app.group_attribute_statements != null ? local.group_attribute_statements : []
    )
  app_settings = var.saml_app.custom_settings != null ? jsonencode(var.saml_app.custom_settings) : null

}

resource "okta_app_saml" "saml_app" {
  // Basic app configuration
  label             = local.saml_label
  status            = var.saml_app.status
  preconfigured_app = var.saml_app.preconfigured_app


  // Visual/UI settings
  logo                = var.saml_app.logo
  admin_note          = jsonencode(local.admin_note)
  enduser_note        = var.saml_app.enduser_note
  hide_ios            = var.saml_app.hide_ios
  hide_web            = var.saml_app.hide_web
  auto_submit_toolbar = var.saml_app.auto_submit_toolbar

  // Accessibility settings
  accessibility_self_service       = var.saml_app.accessibility_self_service
  accessibility_error_redirect_url = var.saml_app.accessibility_error_redirect_url
  accessibility_login_redirect_url = var.saml_app.accessibility_login_redirect_url

  // Authentication policy
  authentication_policy = local.authentication_policy_id
  implicit_assignment   = var.saml_app.implicit_assignment

  // User management settings
  user_name_template             = var.saml_app.user_name_template
  user_name_template_type        = var.saml_app.user_name_template_type
  user_name_template_suffix      = var.saml_app.user_name_template_suffix
  user_name_template_push_status = var.saml_app.user_name_template_push_status

  // SAML protocol settings
  saml_version            = var.saml_app.saml_version
  assertion_signed        = var.saml_app.assertion_signed
  response_signed         = var.saml_app.response_signed
  signature_algorithm     = var.saml_app.signature_algorithm
  digest_algorithm        = var.saml_app.digest_algorithm
  honor_force_authn       = var.saml_app.honor_force_authn
  authn_context_class_ref = var.saml_app.authn_context_class_ref
  idp_issuer              = var.saml_app.idp_issuer

  // SAML subject configuration
  subject_name_id_format   = var.saml_app.subject_name_id_format
  subject_name_id_template = var.saml_app.subject_name_id_template

  // Endpoint configuration
  acs_endpoints       = var.saml_app.acs_endpoints
  sso_url             = var.saml_app.sso_url
  destination         = local.destination
  recipient           = local.recipient
  audience            = var.saml_app.audience
  default_relay_state = var.saml_app.default_relay_state
  sp_issuer           = var.saml_app.sp_issuer

  // Single logout configuration
  single_logout_url         = var.saml_app.single_logout_url
  single_logout_certificate = var.saml_app.single_logout_certificate
  single_logout_issuer      = var.saml_app.single_logout_issuer

  // Advanced SAML settings
  request_compressed          = var.saml_app.request_compressed
  saml_signed_request_enabled = var.saml_app.saml_signed_request_enabled
  inline_hook_id              = var.saml_app.inline_hook_id

  // Certificate settings
  key_name        = var.saml_app.key_name
  key_years_valid = var.saml_app.key_years_valid

  // App settings (JSON format)
  app_settings_json = local.app_settings
  app_links_json    = local.app_links_json

  //Attribute statements
    dynamic "attribute_statements" {
      for_each = local.attribute_statements_combined 
      content {
        name      = attribute_statements.value.name
        namespace = attribute_statements.value.namespace
        type      = attribute_statements.value.type

        #Only set these if type is EXPRESSION
        values    = attribute_statements.value.type == "EXPRESSION" ? attribute_statements.value.values : null
        
        # Only set these if type is GROUP
        filter_type  = attribute_statements.value.type == "GROUP" ? attribute_statements.value.filterType : null
        filter_value = attribute_statements.value.type == "GROUP" ? attribute_statements.value.filterValue : null
      }
    }
  }
locals {
  find_app_url =  "https://${var.environment.org_name}.${var.environment.base_url}/api/v1/apps?includeNonDeleted=false&q=${local.saml_label}"

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

#
##### These two data sources are the same purpose. after testing data.http.schema will be replaced
data "okta_user_profile_mapping_source" "testing" {
  count = saml_app_id != "none" ? 1 : 0 
  id = local.saml_app_id
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
      condition = local.saml_app_id == "none" || local.saml_app_id == try(okta_app_saml.saml_app.id, "n/a")
      error_message = "An application with label '${local.saml_label}' already exists in Okta outside of Terraform. Either modify the label in your configuration or delete/rename the existing application in Okta."
    }

    # Check schema API response
    precondition {
      condition = data.http.schema.status_code == 200 || local.saml_app_id == "none"
      error_message = "Schema API request failed with status code: ${data.http.schema.status_code}. Error: ${data.http.schema.response_body}"
    }
  }
}





locals {

  

  schema_transformation_status = try(jsondecode(data.http.schema.response_body).definitions.base,"Application does not exist" 
    ) != {
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
  } || var.schema == [{
      index       = "userName"
      master      = "PROFILE_MASTER"
      pattern     = tostring(null)
      permissions = "READ_ONLY"
      required    = true
      title       = "Username"
      type        = "string"
      user_type   = "default"
    }] ? "transformation complete or no transformation required" : "pre-transformation"

      # Base schema items
  base_schema_raw = [
    for item in var.schema : {
      index       = item.id
      title       = item.title
      type        = item.schema_type
      master      = item.master != null ? item.master : "PROFILE_MASTER"
      pattern     = item.pattern
      permissions = item.permissions != null ? item.permissions : "READ_ONLY"
      required    = item.required != null ? item.required : true
      user_type   = item.user_type != null ? item.user_type : "default"
    }
    if item.base_schema == true
  ]
  

  base_schema = local.schema_transformation_status == "pre-transformation" ? [{
    index       = "userName"
    master      = "PROFILE_MASTER"
    pattern     = null
    permissions = "READ_ONLY"
    required    = true
    title       = "Username"
    type        = "string"
    user_type   = "default"
  }] : local.base_schema_raw
}

resource "okta_app_user_base_schema_property" "properties" {
  count = length(local.base_schema)

  app_id      = okta_app_saml.saml_app.id
  index       = local.base_schema[count.index].index
  title       = local.base_schema[count.index].title
  type        = local.base_schema[count.index].type
  master      = local.base_schema[count.index].master
  pattern     = local.base_schema[count.index].pattern
  permissions = local.base_schema[count.index].permissions
  required    = local.base_schema[count.index].required
  user_type   = local.base_schema[count.index].user_type
}

locals {
    # Custom schema items
  custom_schema = [
    for item in var.schema : {
      index              = item.id
      title              = item.title
      type               = item.schema_type
      description        = item.description
      master             = item.master != null ? item.master : "PROFILE_MASTER"
      scope              = item.scope != null ? item.scope : "NONE"
      array_enum         = item.array_enum
      array_type         = item.array_type
      enum               = item.enum
      external_name      = item.external_name
      external_namespace = item.external_namespace
      max_length         = item.max_length
      min_length         = item.min_length
      permissions        = item.permissions != null ? item.permissions : "READ_ONLY"
      required           = item.required != null ? item.required : false
      union              = item.union != null ? item.union : false
      unique             = item.unique != null ? item.unique : "NOT_UNIQUE"
      user_type          = item.user_type != null ? item.user_type : "default"
      one_of             = item.one_of
      array_one_of       = item.array_one_of
    }
    if item.base_schema == false
  ]
 
}


resource "okta_app_user_schema_property" "custom_schema" {
  for_each = { for idx, prop in local.custom_schema : prop.index => prop }

  app_id      = okta_app_saml.saml_app.id
  index       = each.value.index
  title       = each.value.title
  type        = each.value.type
  description = each.value.description
  master      = each.value.master
  scope       = each.value.scope

  dynamic "array_one_of" {
    for_each = each.value.array_one_of != null ? each.value.array_one_of : []
    content {
      const = array_one_of.value.const
      title = array_one_of.value.title
    }
  }

  array_enum         = each.value.array_enum
  array_type         = each.value.array_type
  enum               = each.value.enum
  external_name      = each.value.external_name
  external_namespace = each.value.external_namespace
  max_length         = each.value.max_length
  min_length         = each.value.min_length
  permissions        = each.value.permissions
  required           = each.value.required
  union              = each.value.union
  unique             = each.value.unique
  user_type          = each.value.user_type

  dynamic "one_of" {
    for_each = each.value.one_of != null ? each.value.one_of : []
    content {
      const = one_of.value.const
      title = one_of.value.title
    }
  }
}

locals {
  to_app_mappings = [
    for item in var.schema : {
      id          = item.id
      expression  = item.to_app_mapping.expression
      push_status = item.to_app_mapping.push_status
    }
    if item.to_app_mapping != null
  ]
}

# Fetch the user profile mapping source
data "okta_user_profile_mapping_source" "user" {}

# Create a flexible profile mapping resource that uses the variable
resource "okta_profile_mapping" "to_app_mapping" {
  source_id          = data.okta_user_profile_mapping_source.user.id
  target_id          = okta_app_saml.saml_app.id
  #delete_when_absent = var.delete_when_absent
  #always_apply       = var.always_apply

  # Dynamically create mappings based on the variable
  dynamic "mappings" {
    for_each = local.to_app_mappings
    content {
      id         = mappings.value.id
      expression = mappings.value.expression
      push_status = mappings.value.push_status
    }
  }
}

locals {
  to_okta_mappings = [
    for item in var.schema : {
      id          = item.id
      expression  = item.to_okta_mapping.expression
      push_status = item.to_okta_mapping.push_status
    }
    if item.to_okta_mapping != null
  ]
}

# Create a flexible profile mapping resource that uses the variable
resource "okta_profile_mapping" "to_okta_mapping" {
  source_id          = okta_app_saml.saml_app.id
  target_id          = data.okta_user_profile_mapping_source.user.id
  #delete_when_absent = var.delete_when_absent
  #always_apply       = var.always_apply

  # Dynamically create mappings based on the variable
  dynamic "mappings" {
    for_each = local.to_okta_mappings
    content {
      id         = mappings.value.id
      expression = mappings.value.expression
      push_status = mappings.value.push_status
    }
  }
}


resource "okta_app_group_assignments" "main_app" {
  app_id = okta_app_saml.saml_app.id

  dynamic "group" {
    for_each = okta_group.assignment_groups[*].id
    iterator = group_id
    content {
      id       = group_id.value
      profile  = local.schema_transformation_status == "transformation complete or no transformation required"? jsonencode(
        var.roles[group_id.key].profile) : jsonencode({})
      priority = tonumber(group_id.key) + 1
    }
  }
}