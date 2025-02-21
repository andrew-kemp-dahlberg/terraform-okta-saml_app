resource "okta_group" "assignment_groups" {
  count       = length(var.roles)
  name        = "APP-ROLE-${upper(var.label)}-${upper(var.roles[count.index].role)}"
  description = "Group assigns users to ${label} with the role of ${var.roles[count.index].role}"
}

locals {
  admin_group_description = var.admin_role == {} ? "Group for ${label} super admins. Admin assignment is not automatic and must be assigned within the app" : "Group for ${label} super admins. Privileges are automatically assigned from this group"
}
resource "okta_group" "admin_group" {
  name        = "APP-ROLE-${upper(var.label)}-SUPERADMIN"
  description = local.admin_group_description
}


resource "okta_app_signon_policy" "authentication_policy" {
  description = "Authentication Policy for ${var.label}"
  name        = "${var.label} Authentication Policy"
}

locals {
  computer_assurances = compact(
    try(var.device_assurances_policy_ids.Mac, null),
    try(var.device_assurance_policy_ids.Windows, null)
    ) == null ? null : compact(
    try(var.device_assurances_policy_ids.Mac, null),
    try(var.device_assurances_policy_ids.Windows, null)
  )

  mobile_assurances = compact(
    try(var.device_assurances_policy_ids.iOS, null),
    try(var.device_assurance_policy_ids.Android, null)
    ) == null ? null : compact(
    try(var.device_assurances_policy_ids.iOS, null),
    try(var.device_assurances_policy_ids.Android, null)
  )

  admin_assurances = compact(

    try(var.device_assurances_policy_ids.Mac, null),
    try(var.device_assurance_policy_ids.Windows, null),
    try(var.device_assurances_policy_ids.iOS, null),
    try(var.device_assurances_policy_ids.Android, null)
    ) == null ? null : compact(

    try(var.device_assurances_policy_ids.Mac, null),
    try(var.device_assurance_policy_ids.Windows, null),
    try(var.device_assurances_policy_ids.iOS, null),
    try(var.device_assurances_policy_ids.Android, null)
  )

  auth_rules = var.authentication_policy_rules == null ? [
    {
      name                       = "Super Admin Authentication Policy Rule"
      constraints                = ["{\"possession\":{\"required\":true,\"hardwareProtection\":\"REQUIRED\",\"userPresence\":\"REQUIRED\",\"userVerification\":\"REQUIRED\"}}"]
      groups_included            = [okta_group.admin_group.id]
      device_assurances_included = local.admin_assurances
      device_is_managed          = true
      device_is_registered       = true
    },
    {
      name                       = "Mac and Windows Devices"
      constraints                = ["{\"possession\":{\"required\":true,\"hardwareProtection\":\"REQUIRED\",\"userPresence\":\"REQUIRED\",\"userVerification\":\"REQUIRED\"}}"]
      device_assurances_included = local.computer_assurances
    },
    {
      name                       = "Android and iOS devices"
      constraints                = ["{\"knowledge\":{\"required\":false},\"possession\":{\"authenticationMethods\":[{\"key\":\"okta_verify\",\"method\":\"signed_nonce\"}],\"required\":false,\"hardwareProtection\":\"REQUIRED\",\"phishingResistant\":\"REQUIRED\",\"userPresence\":\"REQUIRED\"}}"]
      device_assurances_included = local.mobile_assurances
    },
    {
      name        = "Unsupported Devices"
      constraints = ["{\"knowledge\":{\"reauthenticateIn\":\"PT43800H\",\"types\":[\"password\"],\"required\":true},\"possession\":{\"required\":true,\"hardwareProtection\":\"REQUIRED\",\"userPresence\":\"REQUIRED\"}}"]
      platform_includes = [
        { os_type = "CHROMEOS", type = "DESKTOP" },
        { os_type = "OTHER", type = "DESKTOP" },
        { os_type = "OTHER", type = "MOBILE" }
      ]
    }
  ] : var.authentication_policy_rules

}

resource "okta_app_signon_policy_rule" "authentication_policy_rule" {
  count = length(local.auth_rules)

  name                        = local.auth_rules[count.index].name
  constraints                 = local.auth_rules[count.index].constraints
  policy_id                   = okta_app_signon_policy.authentication_policy.id
  access                      = local.auth_rules[count.index].access
  custom_expression           = local.auth_rules[count.index].custom_expression
  device_assurances_included  = local.auth_rules[count.index].device_assurances_included
  device_is_managed           = local.auth_rules[count.index].device_is_managed
  device_is_registered        = local.auth_rules[count.index].device_is_registered
  factor_mode                 = local.auth_rules[count.index].factor_mode
  groups_excluded             = local.auth_rules[count.index].groups_excluded
  groups_included             = local.auth_rules[count.index].groups_included
  inactivity_period           = local.auth_rules[count.index].inactivity_period
  network_connection          = local.auth_rules[count.index].network_connection
  network_excludes            = local.auth_rules[count.index].network_excludes
  network_includes            = local.auth_rules[count.index].network_includes
  priority                    = count.index + 1
  re_authentication_frequency = local.auth_rules[count.index].re_authentication_frequency
  risk_score                  = local.auth_rules[count.index].risk_score
  status                      = local.auth_rules[count.index].status
  type                        = local.auth_rules[count.index].type
  user_types_excluded         = local.auth_rules[count.index].user_types_excluded
  user_types_included         = local.auth_rules[count.index].user_types_included
  users_excluded              = local.auth_rules[count.index].users_excluded
  users_included              = local.auth_rules[count.index].users_included

  dynamic "platform_include" {
    for_each = local.auth_rules[count.index].platform_includes
    content {
      os_expression = platform_include.value.os_expression
      os_type       = platform_include.value.os_type
      type          = platform_include.value.type
    }
  }
}

locals {
  recipient   = var.recipient == null ? var.sso_url : var.recipient
  destination = var.destination == null ? var.sso_url : var.destination

  attribute_statements = [
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
}

resource "okta_app_saml" "saml_app" {
  accessibility_error_redirect_url = var.accessibility_error_redirect_url
  accessibility_login_redirect_url = var.accessibility_login_redirect_url
  accessibility_self_service       = var.accessibility_self_service
  acs_endpoints                    = var.acs_endpoints
  admin_note                       = var.admin_note
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
    for_each = local.attribute_statements
    iterator = attr

    content {
      name         = attr.value.name
      type         = attr.value.type
      values       = attr.value.values
      filter_type  = attr.value.filter_type
      filter_value = attr.value.filter_value
      namespace    = attr.value.namespace
    }
  }
}
locals {
  profile = concat(var.admin_role, [for assignment in var.roles.profile : assignment])
}
resource "okta_app_group_assignments" "main_app" {
  app_id = okta_app_saml.saml_app.id
  dynamic "profiles" {
    for_each = local.profile
    iterator = attr
    content {
      priority = count.index + 1
      profile  = jsonencode(attr.profiles)
    }
  }
}