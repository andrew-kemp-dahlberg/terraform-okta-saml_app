locals {
  authentication_policy_name = ${var.label}
}
resource "okta_app_signon_policy" "authentication_policy" {
  description = "Default policy that requir"
  name        = "Any two factors"
}

resource "okta_app_signon_policy_rule" "authentication_policy_rule" {
  access                      = "ALLOW"
  constraints                 = ["{\"possession\":{\"required\":true,\"hardwareProtection\":\"REQUIRED\",\"userPresence\":\"REQUIRED\",\"userVerification\":\"REQUIRED\"}}"]
  custom_expression           = null
  device_assurances_included  = null
  device_is_managed           = null
  device_is_registered        = null
  factor_mode                 = "2FA"
  groups_excluded             = []
  groups_included             = ["00g11p7vbcqI3vXBt2p8"]
  inactivity_period           = null
  name                        = "Mac and Windows Devices"
  network_connection          = "ANYWHERE"
  network_excludes            = null
  network_includes            = null
  policy_id                   = okta_app_signon_policy.authentication_policy.id
  priority                    = 1
  re_authentication_frequency = "PT43800H"
  risk_score                  = "ANY"
  status                      = "ACTIVE"
  type                        = "ASSURANCE"
  user_types_excluded         = []
  user_types_included         = []
  users_excluded              = []
  users_included              = []
  platform_include {
    os_expression = null
    os_type       = "MACOS"
    type          = "DESKTOP"
  }
  platform_include {
    os_expression = null
    os_type       = "WINDOWS"
    type          = "DESKTOP"
  }
}

resource "okta_app_signon_policy_rule" "authentication_policy_rule" {
  access                      = "ALLOW"
  constraints                 = ["{\"knowledge\":{\"required\":false},\"possession\":{\"authenticationMethods\":[{\"key\":\"okta_verify\",\"method\":\"signed_nonce\"}],\"required\":false,\"hardwareProtection\":\"REQUIRED\",\"phishingResistant\":\"REQUIRED\",\"userPresence\":\"REQUIRED\"}}"]
  custom_expression           = null
  device_assurances_included  = ["daeya6jtpsaMCFM4h2p7", "daeya6odzfBCEPM8F2p7"]
  device_is_managed           = false
  device_is_registered        = false
  factor_mode                 = "2FA"
  groups_excluded             = []
  groups_included             = ["00g11p7vbcqI3vXBt2p8"]
  inactivity_period           = null
  name                        = "Android and iOS devices"
  network_connection          = "ANYWHERE"
  network_excludes            = null
  network_includes            = null
  policy_id                   = "rsto89gt30Dn9uLiy2p7"
  priority                    = 2
  re_authentication_frequency = "PT43800H"
  risk_score                  = "ANY"
  status                      = "ACTIVE"
  type                        = "ASSURANCE"
  user_types_excluded         = []
  user_types_included         = []
  users_excluded              = []
  users_included              = []
}

resource "okta_app_signon_policy_rule" "authentication_policy_rule" {
  access                      = "ALLOW"
  constraints                 = ["{\"knowledge\":{\"reauthenticateIn\":\"PT43800H\",\"types\":[\"password\"],\"required\":true},\"possession\":{\"required\":true,\"hardwareProtection\":\"REQUIRED\",\"userPresence\":\"REQUIRED\"}}"]
  custom_expression           = null
  device_assurances_included  = null
  device_is_managed           = null
  device_is_registered        = null
  factor_mode                 = "2FA"
  groups_excluded             = null
  groups_included             = null
  inactivity_period           = null
  name                        = "Unsupported Devices"
  network_connection          = "ANYWHERE"
  network_excludes            = null
  network_includes            = null
  policy_id                   = "rsto89gt30Dn9uLiy2p7"
  priority                    = 3
  re_authentication_frequency = "PT43800H"
  risk_score                  = "ANY"
  status                      = "ACTIVE"
  type                        = "ASSURANCE"
  user_types_excluded         = []
  user_types_included         = []
  users_excluded              = []
  users_included              = []
  platform_include {
    os_expression = null
    os_type       = "CHROMEOS"
    type          = "DESKTOP"
  }
  platform_include {
    os_expression = null
    os_type       = "OTHER"
    type          = "DESKTOP"
  }
  platform_include {
    os_expression = null
    os_type       = "OTHER"
    type          = "MOBILE"
  }
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
    for_each = var.attribute_statements
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