locals {
  roles = concat(
    var.admin_role != {} ? [{
      role    = "Super Admin"
      profile = var.admin_role
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
  name                      = "APP-ROLE-${upper(var.name)}-${upper(local.roles[count.index].role)}"
  description               = "Group assigns users to ${var.name} with the role of ${local.roles[count.index].role}"
  custom_profile_attributes = jsonencode(local.custom_attributes[count.index])
}

locals {
  admin_group_description = var.admin_role == {} ? "Group for ${var.name} super admins. Admin assignment is not automatic and must be assigned within the app" : "Group for ${var.name} super admins. Privileges are automatically assigned from this group"
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
      [try(var.device_assurance_policy_ids.Mac, null)],
      [try(var.device_assurance_policy_ids.Windows, null)],
      [try(var.device_assurance_policy_ids.iOS, null)],
      [try(var.device_assurance_policy_ids.Android, null)]
    )
    ) == [] ? null : compact(
    concat(
      [try(var.device_assurance_policy_ids.Mac, null)],
      [try(var.device_assurance_policy_ids.Windows, null)],
      [try(var.device_assurance_policy_ids.iOS, null)],
      [try(var.device_assurance_policy_ids.Android, null)]
    )
  )


  default_auth_rules = [
    # Rule 1: Super Admin Authentication Policy Rule (not shown in your example but mentioned earlier)
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
  recipient   = var.saml_app_settings.recipient == null ? var.saml_app_settings.sso_url : var.saml_app_settings.recipient
  destination = var.saml_app_settings.destination == null ? var.saml_app_settings.sso_url : var.saml_app_settings.destination

  attribute_statements = var.saml_app_settings.attribute_statements == null ? null : [
    for attr in var.saml_app_settings.attribute_statements : {
      name = attr.name
      namespace = lookup({
        "basic"         = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        "uri reference" = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        "unspecified"   = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
      }, attr.name_format, "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
      type         = attr.type == "user" ? "EXPRESSION" : "GROUP"
      filter_type  = attr.type == "group" ? "REGEX" : null
      filter_value = attr.type == "group" ? attr.filter_value : null
      values       = attr.type == "user" ? attr.values : []
    }
  ]
  attribute_statements_clean = [
    for attr in coalesce(local.attribute_statements, []) : { #local.attribute_statements may need to go back to var.attribute statements. requires testing
      for key, value in {
        name         = attr.name
        type         = attr.type
        values       = attr.values
        filter_type  = attr.filter_type
        filter_value = attr.filter_value
        namespace    = attr.namespace
      } : key => value if value != null
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
  accessibility_error_redirect_url = var.saml_app_settings.accessibility_error_redirect_url
  accessibility_login_redirect_url = var.saml_app_settings.accessibility_login_redirect_url
  accessibility_self_service       = var.saml_app_settings.accessibility_self_service
  acs_endpoints                    = var.saml_app_settings.acs_endpoints
  admin_note                       = jsonencode(local.admin_note)
  assertion_signed                 = var.saml_app_settings.assertion_signed
  audience                         = var.saml_app_settings.audience
  authentication_policy            = okta_app_signon_policy.authentication_policy.id
  authn_context_class_ref          = var.saml_app_settings.authn_context_class_ref
  auto_submit_toolbar              = var.saml_app_settings.auto_submit_toolbar
  default_relay_state              = var.saml_app_settings.default_relay_state
  destination                      = local.destination
  digest_algorithm                 = var.saml_app_settings.digest_algorithm
  enduser_note                     = var.saml_app_settings.enduser_note
  hide_ios                         = var.saml_app_settings.hide_ios
  hide_web                         = var.saml_app_settings.hide_web
  honor_force_authn                = var.saml_app_settings.honor_force_authn
  idp_issuer                       = var.saml_app_settings.idp_issuer
  implicit_assignment              = var.saml_app_settings.implicit_assignment
  inline_hook_id                   = var.saml_app_settings.inline_hook_id
  key_name                         = var.saml_app_settings.key_name
  key_years_valid                  = var.saml_app_settings.key_years_valid
  label                            = var.saml_app_settings.label
  logo                             = var.saml_app_settings.logo
  preconfigured_app                = var.saml_app_settings.preconfigured_app
  recipient                        = local.recipient
  request_compressed               = var.saml_app_settings.request_compressed
  response_signed                  = var.saml_app_settings.response_signed
  saml_signed_request_enabled      = var.saml_app_settings.saml_signed_request_enabled
  saml_version                     = var.saml_app_settings.saml_version
  signature_algorithm              = var.saml_app_settings.signature_algorithm
  single_logout_certificate        = var.saml_app_settings.single_logout_certificate
  single_logout_issuer             = var.saml_app_settings.single_logout_issuer
  single_logout_url                = var.saml_app_settings.single_logout_url
  sp_issuer                        = var.saml_app_settings.sp_issuer
  sso_url                          = var.saml_app_settings.sso_url
  status                           = var.saml_app_settings.status
  subject_name_id_format           = var.saml_app_settings.subject_name_id_format
  subject_name_id_template         = var.saml_app_settings.subject_name_id_template
  user_name_template               = var.saml_app_settings.user_name_template
  user_name_template_push_status   = var.saml_app_settings.user_name_template_push_status
  user_name_template_suffix        = var.saml_app_settings.user_name_template_suffix
  user_name_template_type          = var.saml_app_settings.user_name_template_type

  dynamic "attribute_statements" {
    for_each = local.attribute_statements_clean
    content {
      name         = attribute_statements.value.name
      type         = attribute_statements.value.type
      values       = attribute_statements.value.values
      filter_type  = attribute_statements.value.filter_type
      filter_value = attribute_statements.value.filter_value
      namespace    = attribute_statements.value.namespace
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
      profile  = jsonencode(local.roles[group_id.key].profile)
      priority = tonumber(group_id.key) + 1
    }
  }
}

