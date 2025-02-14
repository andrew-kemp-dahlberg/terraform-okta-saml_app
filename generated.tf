# __generated__ by Terraform
# Please review these resources and move them into your main configuration files.

# __generated__ by Terraform from "0oandia7woukWyBit5d7"
resource "okta_app_saml" "test" {
  accessibility_error_redirect_url = null
  accessibility_login_redirect_url = null
  accessibility_self_service       = false
  acs_endpoints                    = []
  admin_note                       = null
  app_links_json = jsonencode({
    dev-97570053_custom_1_link = true
  })
  app_settings_json              = jsonencode({})
  assertion_signed               = true
  audience                       = "https://test.com"
  authentication_policy          = "rstmibhu24ZCHjsqt5d7"
  authn_context_class_ref        = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
  auto_submit_toolbar            = false
  default_relay_state            = "https://test.com"
  destination                    = "https://test.com"
  digest_algorithm               = "SHA256"
  enduser_note                   = null
  hide_ios                       = false
  hide_web                       = false
  honor_force_authn              = true
  idp_issuer                     = "http://www.okta.com/$${org.externalKey}"
  implicit_assignment            = false
  inline_hook_id                 = null
  key_name                       = null
  key_years_valid                = null
  label                          = "custom"
  logo                           = null
  preconfigured_app              = "dev-97570053_custom_1"
  recipient                      = "https://test.com"
  request_compressed             = null
  response_signed                = true
  saml_signed_request_enabled    = false
  saml_version                   = "2.0"
  signature_algorithm            = "RSA_SHA256"
  single_logout_certificate      = null
  single_logout_issuer           = null
  single_logout_url              = null
  sp_issuer                      = null
  sso_url                        = "https://test.com"
  status                         = "ACTIVE"
  subject_name_id_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  subject_name_id_template       = "$${user.userName}"
  user_name_template             = "$${source.login}"
  user_name_template_push_status = null
  user_name_template_suffix      = null
  user_name_template_type        = "BUILT_IN"
  attribute_statements {
    filter_type  = null
    filter_value = null
    name         = "firstName"
    namespace    = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
    type         = "EXPRESSION"
    values       = ["user.firstName"]
  }
  attribute_statements {
    filter_type  = null
    filter_value = null
    name         = "lastName"
    namespace    = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
    type         = "EXPRESSION"
    values       = ["user.lastName"]
  }
}
