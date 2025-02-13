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
