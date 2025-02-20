# terraform-okta-app


## Input Variable: `attribute_statements`

### Description
This module handles the transformation of SAML attribute statements into a format compatible with SAML providers (e.g., Okta). It includes validations and automatic formatting rules for `user` and `group` attribute types.

A list of objects defining SAML attributes. Each object must specify `type` (`"user"` or `"group"`) and `name`, with optional fields for formatting and filtering.

### Schema
```hcl
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