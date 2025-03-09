locals {
  admin_group_description = var.admin_role == {} ? "Group for ${var.name} super admins. Admin assignment is not automatic and must be assigned within the app" : "Group for ${var.name} super admins. Privileges are automatically assigned from this group"
  #### this is also used to gather regex for group attribute statements
  roles = concat(
    var.admin_role != {} ? [{
      name                = "Super Admin"
      attribute_statement = var.admin_role.attribute_statement
      claim               = var.admin_role.claim
      profile             = var.admin_role.profile
    }] : [],
    var.roles
  )

  profile             = [for role in local.roles : role.profile]
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

  custom_attributes = [for index in range(length(local.roles)) : merge(
    { notes = local.group_notes[index] },
    { assignmentProfile = local.group_profile[index] },
    local.app_group_names != "" ? { applicationAssignments = local.app_group_names } : {},
    local.mailing_group_names != "" ? { mailingLists = local.mailing_group_names } : {},
    local.push_group_names != "" ? { pushGroups = local.push_group_names } : {}
  )]

}

resource "okta_group" "assignment_groups" {
  count                     = length(local.roles)
  name                      = "APP-ROLE-${upper(var.name)}-${upper(local.roles[count.index].name)}"
  description               = "Group assigns users to ${var.name} with the role of ${local.roles[count.index].name}"
  custom_profile_attributes = jsonencode(local.custom_attributes[count.index])
}


locals {
  policy_description = var.authentication_policy_rules == null ? "Authentication Policy for ${var.name}. It is the default policy set by Terraform." : "Authentication Policy for ${var.name}. It is a custom policy set through the terraform app module"
}

resource "okta_app_signon_policy" "authentication_policy" {
  description = local.policy_description
  name        = "${var.name} Authentication Policy"
  catch_all   = false
}

locals {
  device_assurances = compact(
    concat(
      [try(var.environment.device_assurance_policy_ids.Mac, null)],
      [try(var.environment.device_assurance_policy_ids.Windows, null)],
      [try(var.environment.device_assurance_policy_ids.iOS, null)],
      [try(var.environment.device_assurance_policy_ids.Android, null)]
    )
    ) == [] ? null : compact(
    concat(
      [try(var.environment.device_assurance_policy_ids.Mac, null)],
      [try(var.environment.device_assurance_policy_ids.Windows, null)],
      [try(var.environment.device_assurance_policy_ids.iOS, null)],
      [try(var.environment.device_assurance_policy_ids.Android, null)]
    )
  )


  default_auth_rules = [
    # Rule 1: Super Admin Authentication Policy Rule 
    {
      name                        = "Super Admin Authentication Policy Rule"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      status                      = "ACTIVE"
      re_authentication_frequency = "PT0S"
      priority                    = 1
      custom_expression           = null
      network_includes            = null
      network_excludes            = null
      risk_score                  = ""
      inactivity_period           = "PT1H"
      network_connection          = "ANYWHERE"
      device_is_managed           = true
      device_is_registered        = true
      device_assurances_included  = local.device_assurances
      groups_included             = [okta_group.assignment_groups[0].id]
      groups_excluded             = []
      users_included              = []
      users_excluded              = []
      user_types_included         = []
      user_types_excluded         = []
      constraints = [jsonencode({
        knowledge = { required = true }
        possession = {
          authenticationMethods = [{ key = "okta_verify", method = "signed_nonce" }]
          required              = true
          hardwareProtection    = "REQUIRED"
          phishingResistant     = "REQUIRED"
        }
      })]
      platform_include = []
    },

    # Rule 2: Supported Devices
    {
      name                        = "Supported Devices"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      status                      = "ACTIVE"
      re_authentication_frequency = "PT0S"
      priority                    = 2
      custom_expression           = null
      network_includes            = null
      network_excludes            = null
      risk_score                  = ""
      inactivity_period           = "PT43800H"
      network_connection          = "ANYWHERE"
      device_is_managed           = null
      device_is_registered        = true
      device_assurances_included  = local.device_assurances
      groups_included             = []
      groups_excluded             = [okta_group.assignment_groups[0].id]
      users_included              = []
      users_excluded              = []
      user_types_included         = []
      user_types_excluded         = []
      constraints = [jsonencode({
        knowledge = { required = true }
        possession = {
          authenticationMethods = [{ key = "okta_verify", method = "signed_nonce" }]
          required              = true
          hardwareProtection    = "REQUIRED"
          phishingResistant     = "REQUIRED"
        }
      })]
      platform_include = []
    },

    # Rule 3: Unsupported Devices
    {
      name                        = "Unsupported Devices"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      status                      = "ACTIVE"
      re_authentication_frequency = "PT43800H"
      priority                    = 3
      custom_expression           = null
      network_includes            = null
      network_excludes            = null
      risk_score                  = ""
      inactivity_period           = ""
      network_connection          = "ANYWHERE"
      device_is_managed           = null
      device_is_registered        = null
      device_assurances_included  = null
      groups_included             = []
      groups_excluded             = [okta_group.assignment_groups[0].id]
      users_included              = []
      users_excluded              = []
      user_types_included         = []
      user_types_excluded         = []
      constraints = [jsonencode({
        knowledge = {
          reauthenticateIn = "PT43800H"
          types            = ["password"]
          required         = true
        }
        possession = {
          required           = true
          hardwareProtection = "REQUIRED"
        }
      })]
      platform_include = [
        { os_type = "CHROMEOS", type = "DESKTOP" },
        { os_type = "OTHER", type = "DESKTOP" },
        { os_type = "OTHER", type = "MOBILE" }
      ]
    }
  ]

  auth_rules = var.authentication_policy_rules == null ? local.default_auth_rules : var.authentication_policy_rules
}

resource "okta_app_signon_policy_rule" "auth_policy_rules" {
  count                       = length(local.auth_rules)
  policy_id                   = okta_app_signon_policy.authentication_policy.id
  name                        = local.auth_rules[count.index].name
  access                      = try(local.auth_rules[count.index].access, "ALLOW")
  factor_mode                 = try(local.auth_rules[count.index].factor_mode, "2FA")
  type                        = try(local.auth_rules[count.index].type, "ASSURANCE")
  re_authentication_frequency = try(local.auth_rules[count.index].re_authentication_frequency, "PT0S")
  constraints                 = try(local.auth_rules[count.index].constraints, [])
  priority                    = try(local.auth_rules[count.index].priority, count.index + 1)
  status                      = try(local.auth_rules[count.index].status, "ACTIVE")
  custom_expression           = try(local.auth_rules[count.index].custom_expression, null)
  inactivity_period           = try(local.auth_rules[count.index].inactivity_period, "")
  network_connection          = try(local.auth_rules[count.index].network_connection, "ANYWHERE")
  network_includes            = try(local.auth_rules[count.index].network_includes, null)
  network_excludes            = try(local.auth_rules[count.index].network_excludes, null)
  risk_score                  = try(local.auth_rules[count.index].risk_score, "")
  device_is_managed           = try(local.auth_rules[count.index].device_is_managed, null)
  device_is_registered        = try(local.auth_rules[count.index].device_is_registered, null)
  device_assurances_included  = try(local.auth_rules[count.index].device_assurances_included, [])
  groups_included             = try(local.auth_rules[count.index].groups_included, [])
  groups_excluded             = try(local.auth_rules[count.index].groups_excluded, [])
  users_included              = try(local.auth_rules[count.index].users_included, [])
  users_excluded              = try(local.auth_rules[count.index].users_excluded, [])
  user_types_included         = try(local.auth_rules[count.index].user_types_included, [])
  user_types_excluded         = try(local.auth_rules[count.index].user_types_excluded, [])

  dynamic "platform_include" {
    for_each = try(local.auth_rules[count.index].platform_include, [])
    content {
      os_type = platform_include.value.os_type
      type    = platform_include.value.type
    }
  }
}


locals {
  saml_label  = var.saml_app.label == null ? var.name : var.saml_app.label
  recipient   = var.saml_app.recipient == null ? var.saml_app.sso_url : var.saml_app.recipient
  destination = var.saml_app.destination == null ? var.saml_app.sso_url : var.saml_app.destination

  user_attribute_statements = var.saml_app.user_attribute_statements == null ? null : [
    for attr in var.saml_app.user_attribute_statements : {
      type = "EXPRESSION"
      name = attr.name
      namespace = lookup({
        "basic"           = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        "uri reference"   = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        "unspecified"     = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
        # "scim"            = "urn:ietf:params:scim:schemas:core:2.0:User"
        # "scim enterprise" = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
      }, attr.name_format, "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
      values = attr.values
    }
  ]

  admin_note = {
    name = var.admin_note.saas_mgmt_name
    sso  = var.admin_note.sso_enforced
    auto = distinct([
      var.admin_note.lifecycle_automations.provisioning.type,
      var.admin_note.lifecycle_automations.user_updates.type,
      var.admin_note.lifecycle_automations.deprovisioning.type
    ])
    owner = var.admin_note.app_owner
    audit = var.admin_note.last_access_audit_date
  }
}

resource "okta_app_saml" "saml_app" {
  accessibility_error_redirect_url = var.saml_app.accessibility_error_redirect_url
  accessibility_login_redirect_url = var.saml_app.accessibility_login_redirect_url
  accessibility_self_service       = var.saml_app.accessibility_self_service
  acs_endpoints                    = var.saml_app.acs_endpoints
  admin_note                       = jsonencode(local.admin_note)
  assertion_signed                 = var.saml_app.assertion_signed
  audience                         = var.saml_app.audience
  authentication_policy            = okta_app_signon_policy.authentication_policy.id
  authn_context_class_ref          = var.saml_app.authn_context_class_ref
  auto_submit_toolbar              = var.saml_app.auto_submit_toolbar
  default_relay_state              = var.saml_app.default_relay_state
  destination                      = local.destination
  digest_algorithm                 = var.saml_app.digest_algorithm
  enduser_note                     = var.saml_app.enduser_note
  hide_ios                         = var.saml_app.hide_ios
  hide_web                         = var.saml_app.hide_web
  honor_force_authn                = var.saml_app.honor_force_authn
  idp_issuer                       = var.saml_app.idp_issuer
  implicit_assignment              = var.saml_app.implicit_assignment
  inline_hook_id                   = var.saml_app.inline_hook_id
  key_name                         = var.saml_app.key_name
  key_years_valid                  = var.saml_app.key_years_valid
  label                            = local.saml_label
  logo                             = var.saml_app.logo
  preconfigured_app                = var.saml_app.preconfigured_app
  recipient                        = local.recipient
  request_compressed               = var.saml_app.request_compressed
  response_signed                  = var.saml_app.response_signed
  saml_signed_request_enabled      = var.saml_app.saml_signed_request_enabled
  saml_version                     = var.saml_app.saml_version
  signature_algorithm              = var.saml_app.signature_algorithm
  single_logout_certificate        = var.saml_app.single_logout_certificate
  single_logout_issuer             = var.saml_app.single_logout_issuer
  single_logout_url                = var.saml_app.single_logout_url
  sp_issuer                        = var.saml_app.sp_issuer
  sso_url                          = var.saml_app.sso_url
  status                           = var.saml_app.status
  subject_name_id_format           = var.saml_app.subject_name_id_format
  subject_name_id_template         = var.saml_app.subject_name_id_template
  user_name_template               = var.saml_app.user_name_template
  user_name_template_push_status   = var.saml_app.user_name_template_push_status
  user_name_template_suffix        = var.saml_app.user_name_template_suffix
  user_name_template_type          = var.saml_app.user_name_template_type
  dynamic "attribute_statements" {
    for_each = local.user_attribute_statements
    content {
      name      = attribute_statements.value.name
      type      = attribute_statements.value.type
      values    = attribute_statements.value.values
      namespace = attribute_statements.value.namespace
    }
  }
}

locals {
  # Check if group attribute statement exists
  group_attribute_exists = local.group_attribute_statements != null ? 1 : 0

  # Format the group attribute statements as a list of objects

  # Find roles with claim = true
  attribute_statement_roles = [
    for role in local.roles : role
    if role.attribute_statement == true
  ]

  # Create a regex pattern matching any group name that corresponds to roles with claim = true
  # This pattern will match: APP-ROLE-APPNAME-ROLENAME where ROLENAME is any role with claim = true
  group_attribute_statements_regex = length(local.attribute_statement_roles) > 0 ? format(
    "^APP-ROLE-%s-(%s)$",
    upper(var.name),
    join("|", [for role in local.attribute_statement_roles : upper(role.name)])
  ) : "^$" # Empty regex if no claim roles exist

  group_attribute_statements = var.saml_app.group_attribute_statements != null ? jsonencode(
    { attributeStatements = [
      {
        type = "GROUP"
        name = var.saml_app.group_attribute_statements.name
        namespace = lookup({
          "basic"         = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
          "uri reference" = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
          "unspecified"   = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
          # "scim"          = "urn:ietf:params:scim:schemas:core:2.0:Group"
        }, var.saml_app.group_attribute_statements.namespace, "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
        filterType  = "REGEX"
        filterValue = local.group_attribute_statements_regex
      }
  ] }) : null

}


resource "okta_app_saml_app_settings" "group_attribute_statements" {
  count    = local.group_attribute_exists
  app_id   = okta_app_saml.saml_app.id
  settings = jsonencode(local.group_attribute_statements)
}


resource "okta_app_group_assignments" "main_app" {
  app_id = okta_app_saml.saml_app.id

  dynamic "group" {
    for_each = okta_group.assignment_groups[*].id
    iterator = group_id
    content {
      id       = group_id.value
      profile  = jsonencode(local.roles[group_id.key].profile)
      priority = tonumber(group_id.key) + 1
    }
  }
}

