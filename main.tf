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
  find_app_url =  "https://${var.environment.org_name}.${var.environment.base_url}/api/v1/apps?q=${local.saml_label}&filter=status eq \"ACTIVE\"&includeNonDeleted=false"
  config_applied = try(length(okta_app_saml.saml_app)) > 0 ? 1 : 0 

}

data "http" "saml_app" {
  url = local.find_app_url
    method = "GET"
    request_headers = {
      Accept = "application/json"
      Authorization = "SSWS ${var.environment.api_token}"
  }
}

locals {
  http_saml_app = try(jsondecode(data.http.saml_app.response_body), [])
  app_id_list = [
    for app in local.http_saml_app : app.id
  ]
  potential_match = length(local.app_id_list) == 0 ? "not applied" : "potential match"

  saml_app_id = try(local.app_id_list[0],"none")
  base_schema_url =  "https://${var.environment.org_name}.${var.environment.base_url}/api/v1/meta/schemas/apps/${local.saml_app_id}/default"
  schema_api_call = [{
    url = local.base_schema_url
    method = "GET"
    request_headers = {
      Accept = "application/json"
      Authorization = "SSWS ${var.environment.api_token}"
  }}]
}

data "http" "schema" {
    url = local.base_schema_url
    method = "GET"
    request_headers = {
      Accept = "application/json"
      Authorization = "SSWS ${var.environment.api_token}"
  }
}

locals {
  current_schema = try(jsondecode(data.http.schema.response_body), {})
  http_schema = length(data.http.schema) > 0 ? data.http.schema.response_body : "\"status\" = \"pre-apply\""
  # First check if the response is an error
  schema_is_error = try(jsondecode(local.http_schema).errorCode != null, false)
  
  # If there's an error or the structure doesn't match expectations, consider it "pre-transformation"
  schema_transformation_status = local.schema_is_error ? "pre-transformation" : (
    try(
      jsondecode(local.http_schema).definitions.base == {
        "id" = "#base"
        "properties" = {
          "userName" = {
            "master" = {
              "type" = "PROFILE_MASTER"
            }
            "maxLength" = 100
            "required" = true
            "scope" = "NONE"
            "title" = "Username"
            "type" = "string"
          }
        }
        "required" = [
          "userName",
        ]
        "type" = "object"
      } && var.base_schema != [{
        index       = "userName"
        master      = "PROFILE_MASTER"
        pattern     = null
        permissions = "READ_ONLY"
        required    = true
        title       = "Username"
        type        = "string"
        user_type   = "default"
      }],
      false
    ) ? "pre-transformation" : "transformed or no transformation required"
  )

  base_schema = local.schema_transformation_status == "pre-transformation" ? [{
    index       = "userName"
    master      = "PROFILE_MASTER"
    pattern     = null
    permissions = "READ_ONLY"
    required    = true
    title       = "Username"
    type        = "string"
    user_type   = "default"
  }] : var.base_schema
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


resource "okta_app_user_schema_property" "custom_properties" {
  for_each = { for idx, prop in var.custom_schema : prop.index => prop }

  app_id      = okta_app_saml.saml_app.id
  index       = each.value.index
  title       = each.value.title
  type        = each.value.type
  description = each.value.description
  master      = each.value.master
  scope       = each.value.scope

  # Optional properties
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

resource "okta_app_group_assignments" "main_app" {
  app_id = okta_app_saml.saml_app.id

  dynamic "group" {
    for_each = okta_group.assignment_groups[*].id
    iterator = group_id
    content {
      id       = group_id.value
      profile  = jsonencode(var.roles[group_id.key].profile)
      priority = tonumber(group_id.key) + 1
    }
  }
}

