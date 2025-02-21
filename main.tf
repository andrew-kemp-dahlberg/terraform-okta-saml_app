# locals {
#   assignments = [
#     for attr in var.attribute_statements : {
#       name = attr.name
#       namespace = lookup({
#         "basic"         = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
#         "uri reference" = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
#         "unspecified"   = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
#       }, attr.name_format, "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
#       type         = attr.type == "user" ? "EXPRESSION" : "GROUP"
#       filter_type  = attr.type == "group" ? "REGEX" : null
#       filter_value = attr.type == "group" ? attr.filter_value : null
#       values       = attr.type == "user" ? attr.values : []
#     }
#   ]
# }


resource "okta_group" "assignment_groups" {
  count = length(var.assignments)
  name = "APP-ROLE-${upper(var.label)}-${upper(var.assignments[count.index].role)}"
  description = "Group assigns users to ${label} with the role of ${var.assignments[count.index].role}"
}

locals {
admin_group_description = var.admin_assignment == {} ? "Group for ${label} super admins. Admin assignment is not automatic and must be assigned within the app" : "Group for ${label} super admins. Privileges are automatically assigned from this group"
}
resource "okta_group" "admin_group" {
  name        = "APP-ROLE-${upper(var.label)}-SUPERADMIN"
  description = local.admin_group_description
}

resource "okta_app_signon_policy" "authentication_policy" {
  description = "Policy for ${var.label}"
  name        = "${var.label} Authentication Policy"
}


resource "okta_app_signon_policy_rule" "authentication_policy_rule" {
  count = length(var.signon_policy_rules)

  # Required attributes
  name        = var.signon_policy_rules[count.index].name
  constraints = var.signon_policy_rules[count.index].constraints
  policy_id   = okta_app_signon_policy.authentication_policy.id

  # Dynamically set optional attributes
  access                      = var.signon_policy_rules[count.index].access
  custom_expression           = var.signon_policy_rules[count.index].custom_expression
  device_assurances_included  = var.signon_policy_rules[count.index].device_assurances_included
  device_is_managed           = var.signon_policy_rules[count.index].device_is_managed
  device_is_registered        = var.signon_policy_rules[count.index].device_is_registered
  factor_mode                 = var.signon_policy_rules[count.index].factor_mode
  groups_excluded             = var.signon_policy_rules[count.index].groups_excluded
  groups_included             = var.signon_policy_rules[count.index].groups_included
  inactivity_period           = var.signon_policy_rules[count.index].inactivity_period
  network_connection          = var.signon_policy_rules[count.index].network_connection
  network_excludes            = var.signon_policy_rules[count.index].network_excludes
  network_includes            = var.signon_policy_rules[count.index].network_includes
  priority                    = count.index + 1
  re_authentication_frequency = var.signon_policy_rules[count.index].re_authentication_frequency
  risk_score                  = var.signon_policy_rules[count.index].risk_score
  status                      = var.signon_policy_rules[count.index].status
  type                        = var.signon_policy_rules[count.index].type
  user_types_excluded         = var.signon_policy_rules[count.index].user_types_excluded
  user_types_included         = var.signon_policy_rules[count.index].user_types_included
  users_excluded              = var.signon_policy_rules[count.index].users_excluded
  users_included              = var.signon_policy_rules[count.index].users_included

  dynamic "platform_include" {
    for_each = var.signon_policy_rules[count.index].platform_includes
    content {
      os_expression = platform_include.value.os_expression
      os_type       = platform_include.value.os_type
      type          = platform_include.value.type
    }
  }
}

locals {
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
  destination                      = var.destination
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
  recipient                        = var.recipient
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


