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
    var.label,
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
  name                      = "APP-ROLE-${upper(var.label)}-${upper(local.roles[count.index].role)}"
  description               = "Group assigns users to ${var.label} with the role of ${local.roles[count.index].role}"
  custom_profile_attributes = jsonencode(local.custom_attributes[count.index])
}

locals {
  admin_group_description = var.admin_role == {} ? "Group for ${var.label} super admins. Admin assignment is not automatic and must be assigned within the app" : "Group for ${var.label} super admins. Privileges are automatically assigned from this group" # Fixed var.label
}

locals {
  policy_description = var.authentication_policy_rules == null ? "Authentication Policy for ${var.label}. It is the default policy set by Terraform." : "Authentication Policy for ${var.label}. It is a custom policy set through the terraform app module"
}

resource "okta_app_signon_policy" "authentication_policy" {
  description = local.policy_description
  name        = "${var.label} Authentication Policy"
  catch_all   = false
}

locals {
  computer_assurances = compact(
    concat(
      [try(var.device_assurance_policy_ids.Mac, null)],
      [try(var.device_assurance_policy_ids.Windows, null)]
    )
    ) == [] ? null : compact(
    concat(
      [try(var.device_assurance_policy_ids.Mac, null)],
      [try(var.device_assurance_policy_ids.Windows, null)]
    )
  )

  mobile_assurances = compact(
    concat(
      [try(var.device_assurance_policy_ids.iOS, null)],
      [try(var.device_assurance_policy_ids.Android, null)]
    )
    ) == [] ? null : compact(
    concat(
      [try(var.device_assurance_policy_ids.iOS, null)],
      [try(var.device_assurance_policy_ids.Android, null)]
    )
  )

  admin_assurances = compact(
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
    {
      name                        = "Super Admin Authentication Policy Rule"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      re_authentication_frequency = "PT43800H"
      groups_included             = [okta_group.assignment_groups[0].id]
      device_is_managed           = true
      device_is_registered        = true
      device_assurances_included  = local.admin_assurances
      constraints = [
        jsonencode({
          "authenticator" : {
            "constraints" : [{
              "methods" : [
                {
                  "type" : "password"
                }
              ],
              "types" : ["password"]
            }]
          },
          "verificationMethod" : {
            "factorMode" : "2FA",
            "type" : "ASSURANCE",
            "reauthenticateIn" : "PT43800H"
          }
        })
      ]
    },
    {
      name                        = "Mac and Windows Devices"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      re_authentication_frequency = "PT43800H"
      device_assurances_included  = local.computer_assurances
      constraints = [
        jsonencode({
          "authenticator" : {
            "constraints" : [{
              "methods" : [
                {
                  "type" : "password"
                }
              ],
              "types" : ["password"]
            }]
          },
          "verificationMethod" : {
            "factorMode" : "2FA",
            "type" : "ASSURANCE",
            "reauthenticateIn" : "PT43800H"
          }
        })
      ]
    },
    {
      name                        = "Android and iOS devices"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      re_authentication_frequency = "PT43800H"
      device_assurances_included  = local.mobile_assurances
      constraints = [
        jsonencode({
          "authenticator" : {
            "constraints" : [{
              "methods" : [
                {
                  "type" : "otp"
                }
              ],
              "types" : ["app"]
            }]
          },
          "verificationMethod" : {
            "factorMode" : "2FA",
            "type" : "ASSURANCE",
            "reauthenticateIn" : "PT43800H"
          }
        })
      ]
    },
    {
      name                        = "Unsupported Devices"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      re_authentication_frequency = "PT43800H"
      platform_include = [
        {
          os_type = "CHROMEOS"
          type    = "DESKTOP"
        },
        {
          os_type = "OTHER"
          type    = "DESKTOP"
        },
        {
          os_type = "OTHER"
          type    = "MOBILE"
        }
      ]
      constraints = [
        jsonencode({
          "authenticator" : {
            "constraints" : [{
              "methods" : [
                {
                  "type" : "password"
                }
              ],
              "types" : ["password"]
            }]
          },
          "verificationMethod" : {
            "factorMode" : "2FA",
            "type" : "ASSURANCE",
            "reauthenticateIn" : "PT43800H"
          }
        })
      ]
    }
  ]

  authentication_policy_rules = var.authentication_policy_rules == null ? null : [
    for rule in var.authentication_policy_rules : {
      name = rule.name
      constraints = jsonencode(merge(
        rule.access != null ? { access = rule.access } : {},
        rule.custom_expression != null ? { custom_expression = rule.custom_expression } : {},
        rule.device_assurances_included != null ? { device_assurances_included = rule.device_assurances_included } : {},
        rule.device_is_managed != null ? { device_is_managed = rule.device_is_managed } : {},
        rule.device_is_registered != null ? { device_is_registered = rule.device_is_registered } : {},
        rule.factor_mode != null ? { factor_mode = rule.factor_mode } : {},
        rule.groups_excluded != null ? { groups_excluded = rule.groups_excluded } : {},
        rule.groups_included != null ? { groups_included = rule.groups_included } : {},
        rule.inactivity_period != null ? { inactivity_period = rule.inactivity_period } : {},
        rule.network_connection != null ? { network_connection = rule.network_connection } : {},
        rule.network_excludes != null ? { network_excludes = rule.network_excludes } : {},
        rule.network_includes != null ? { network_includes = rule.network_includes } : {},
        rule.re_authentication_frequency != null ? { re_authentication_frequency = rule.re_authentication_frequency } : {},
        rule.risk_score != null ? { risk_score = rule.risk_score } : {},
        rule.status != null ? { status = rule.status } : {},
        rule.type != null ? { type = rule.type } : {},
        rule.user_types_excluded != null ? { user_types_excluded = rule.user_types_excluded } : {},
        rule.user_types_included != null ? { user_types_included = rule.user_types_included } : {},
        rule.users_excluded != null ? { users_excluded = rule.users_excluded } : {},
        rule.users_included != null ? { users_included = rule.users_included } : {},
        rule.platform_includes != null ? { platform_includes = rule.platform_includes } : {},
        rule.constraints != null ? { constraints = rule.constraints } : {}
      ))
    }
  ]

  auth_rules = local.authentication_policy_rules == null ? local.default_auth_rules : local.authentication_policy_rules
}


resource "okta_app_signon_policy_rule" "auth_policy_rules" {
  count                       = length(local.auth_rules)
  policy_id                   = okta_app_signon_policy.authentication_policy.id
  name                        = local.auth_rules[count.index].name
  access                      = local.auth_rules[count.index].access
  factor_mode                 = local.auth_rules[count.index].factor_mode
  type                        = local.auth_rules[count.index].type
  re_authentication_frequency = local.auth_rules[count.index].re_authentication_frequency
  constraints                 = local.auth_rules[count.index].constraints
  priority                    = count.index + 1

  dynamic "platform_include" {
    for_each = try(local.auth_rules[count.index].platform_include, [])
    content {
      os_type = platform_include.value.os_type
      type    = platform_include.value.type
    }
  }

  device_is_managed          = try(local.auth_rules[count.index].device_is_managed, null)
  device_is_registered       = try(local.auth_rules[count.index].device_is_registered, null)
  groups_included            = try(local.auth_rules[count.index].groups_included, null)
  device_assurances_included = try(local.auth_rules[count.index].device_assurances_included, null)
}

locals {
  recipient   = var.recipient == null ? var.sso_url : var.recipient
  destination = var.destination == null ? var.sso_url : var.destination

  attribute_statements = var.attribute_statements == null ? null : [
    for attr in var.attribute_statements : {
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
    for attr in coalesce(var.attribute_statements, []) : {
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
  accessibility_error_redirect_url = var.accessibility_error_redirect_url
  accessibility_login_redirect_url = var.accessibility_login_redirect_url
  accessibility_self_service       = var.accessibility_self_service
  acs_endpoints                    = var.acs_endpoints
  admin_note                       = jsonencode(local.admin_note)
  assertion_signed                 = var.assertion_signed
  audience                         = var.audience
  authentication_policy            = okta_app_signon_policy.authentication_policy.id
  authn_context_class_ref          = var.authn_context_class_ref
  auto_submit_toolbar              = var.auto_submit_toolbar
  default_relay_state              = var.default_relay_state
  destination                      = local.destination
  digest_algorithm                 = var.digest_algorithm
  enduser_note                     = var.enduser_note
  hide_ios                         = var.hide_ios
  hide_web                         = var.hide_web
  honor_force_authn                = var.honor_force_authn
  idp_issuer                       = var.idp_issuer
  implicit_assignment              = var.implicit_assignment
  inline_hook_id                   = var.inline_hook_id
  key_name                         = var.key_name
  key_years_valid                  = var.key_years_valid
  label                            = var.label
  logo                             = var.logo
  preconfigured_app                = var.preconfigured_app
  recipient                        = local.recipient
  request_compressed               = var.request_compressed
  response_signed                  = var.response_signed
  saml_signed_request_enabled      = var.saml_signed_request_enabled
  saml_version                     = var.saml_version
  signature_algorithm              = var.signature_algorithm
  single_logout_certificate        = var.single_logout_certificate
  single_logout_issuer             = var.single_logout_issuer
  single_logout_url                = var.single_logout_url
  sp_issuer                        = var.sp_issuer
  sso_url                          = var.sso_url
  status                           = var.status
  subject_name_id_format           = var.subject_name_id_format
  subject_name_id_template         = var.subject_name_id_template
  user_name_template               = var.user_name_template
  user_name_template_push_status   = var.user_name_template_push_status
  user_name_template_suffix        = var.user_name_template_suffix
  user_name_template_type          = var.user_name_template_type

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

