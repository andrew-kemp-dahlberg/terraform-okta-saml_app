data "okta_policy" "access" {
  name = var.policy_name
  type = var.policy_type
}

locals {
  app_settings_json = jsonencode({
    accessibility_error_redirect_url = var.accessibility_error_redirect_url
    accessibility_login_redirect_url = var.accessibility_login_redirect_url
    accessibility_self_service       = var.accessibility_self_service
    acs_endpoints                    = var.acs_endpoints
    admin_note                       = var.admin_note
    assertion_signed                 = var.assertion_signed
    audience                         = var.audience
    authentication_policy            = data.okta_policy.access.id
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
    attribute_statements             = var.attribute_statements
  })
}

resource "okta_app_saml" "saml_app" {
  label             = var.label
  app_settings_json = local.app_settings_json
}