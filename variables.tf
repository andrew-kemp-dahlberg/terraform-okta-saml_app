# variables.tf
variable "client_id" {
  description = "Okta Client ID"
  type        = string
  sensitive   = true
}

variable "org_name" {
  description = "Okta org name ie. company"
  type        = string
}

variable "base_url" {
  description = "Okta Base URL ie. okta.com"
  type        = string
}

variable "private_key_id" {
  description = "Okta Oauth private key id"
  type        = string
  sensitive   = true
}

variable "private_key" {
  description = "Okta Oauth private key"
  type        = string
  sensitive   = true
}

variable "policy_name" {
  description = "Name of the Okta policy"
  type        = string
  default     = "Any two factors"
}

variable "policy_type" {
  description = "Type of Okta policy"
  type        = string
  default     = "ACCESS_POLICY"
}

variable "accessibility_error_redirect_url" {
  description = "Custom error page URL"
  type        = string
  default     = null
}

variable "accessibility_login_redirect_url" {
  description = "Custom login redirect URL"
  type        = string
  default     = null
}

variable "accessibility_self_service" {
  description = "Enable self-service"
  type        = bool
  default     = false
}

variable "acs_endpoints" {
  description = "List of ACS endpoints"
  type        = list(string)
  default     = []
}

variable "admin_note" {
  description = "Administrator notes"
  type        = string
  default     = null
}

variable "assertion_signed" {
  description = "Whether SAML assertions are signed"
  type        = bool
  default     = true
}

variable "audience" {
  description = "Audience URI"
  type        = string
  default     = "https://test.com"
}

variable "authn_context_class_ref" {
  description = "Authentication context class reference"
  type        = string
  default     = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
}

variable "auto_submit_toolbar" {
  description = "Display auto-submit toolbar"
  type        = bool
  default     = false
}

variable "default_relay_state" {
  description = "Default relay state"
  type        = string
  default     = "https://test.com"
}

variable "destination" {
  description = "Destination URL"
  type        = string
  default     = "https://test.com"
}

variable "digest_algorithm" {
  description = "Digest algorithm"
  type        = string
  default     = "SHA256"
}

variable "enduser_note" {
  description = "End user notes"
  type        = string
  default     = null
}

variable "hide_ios" {
  description = "Hide on iOS"
  type        = bool
  default     = false
}

variable "hide_web" {
  description = "Hide on web"
  type        = bool
  default     = false
}

variable "honor_force_authn" {
  description = "Honor ForceAuthn"
  type        = bool
  default     = true
}

variable "idp_issuer" {
  description = "IdP issuer URL"
  type        = string
  default     = "http://www.okta.com/$${org.externalKey}"
}

variable "implicit_assignment" {
  description = "Implicit assignment"
  type        = bool
  default     = false
}

variable "inline_hook_id" {
  description = "Inline hook ID"
  type        = string
  default     = null
}

variable "key_name" {
  description = "Key name"
  type        = string
  default     = null
}

variable "key_years_valid" {
  description = "Key validity years"
  type        = number
  default     = null
}

variable "label" {
  description = "Application label"
  type        = string
}

variable "logo" {
  description = "Logo URL"
  type        = string
}

variable "preconfigured_app" {
  description = "Preconfigured application ID"
  type        = string
}

variable "recipient" {
  description = "Recipient URL"
  type        = string
}

variable "request_compressed" {
  description = "Request compressed"
  type        = bool
  default     = null
}

variable "response_signed" {
  description = "Response signed"
  type        = bool
  default     = true
}

variable "saml_signed_request_enabled" {
  description = "SAML signed request enabled"
  type        = bool
  default     = false
}

variable "saml_version" {
  description = "SAML version"
  type        = string
  default     = "2.0"
}

variable "signature_algorithm" {
  description = "Signature algorithm"
  type        = string
  default     = "RSA_SHA256"
}

variable "single_logout_certificate" {
  description = "Single logout certificate"
  type        = string
  default     = null
}

variable "single_logout_issuer" {
  description = "Single logout issuer"
  type        = string
  default     = null
}

variable "single_logout_url" {
  description = "Single logout URL"
  type        = string
  default     = null
}

variable "sp_issuer" {
  description = "SP issuer"
  type        = string
  default     = null
}

variable "sso_url" {
  description = "SSO URL"
  type        = string
}

variable "status" {
  description = "Application status"
  type        = string
  default     = "ACTIVE"
}

variable "subject_name_id_format" {
  description = "Subject name ID format"
  type        = string
  default     = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
}

variable "subject_name_id_template" {
  description = "Subject name ID template"
  type        = string
  default     = "$${user.userName}"
}

variable "user_name_template" {
  description = "Username template"
  type        = string
  default     = "$${source.login}"
}

variable "user_name_template_push_status" {
  description = "Username template push status"
  type        = string
  default     = null
}

variable "user_name_template_suffix" {
  description = "Username template suffix"
  type        = string
  default     = null
}

variable "user_name_template_type" {
  description = "Username template type"
  type        = string
  default     = "BUILT_IN"
}

variable "attribute_statements" {
  description = "List of Objects containing, type (user or group), name, formation, filter_value for group attributes that is a regex, "
  type = list(object({
    type         = string
    name         = string
    name_format  = optional(string, "unspecified")
    filter_value = optional(string, null)
    values       = optional(list(string), [])
  }))
  default = null
}