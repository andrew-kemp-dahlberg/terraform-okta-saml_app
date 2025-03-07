# Okta SAML Application Terraform Module

## Overview

This Terraform module creates and configures a SAML application in Okta with comprehensive settings, authentication policies, and group assignments. It provides a standardized way to manage SAML applications in your Okta organization, including detailed administrative notes, authentication policies, and role-based access controls.

## Features

- Complete SAML application configuration with customizable settings
- Automated group creation for role-based assignments
- Configurable authentication policies with device assurance support
- Detailed administrative documentation embedded in the application
- Support for attribute statements and mappings
- Role-based access controls with profile mappings

## Requirements

 Name  Version  terraform  >= 1.0.0  okta  ~> 4.13.1 

## Providers

 Name  Version  okta  ~> 4.13.1 

## Authentication

This module requires Okta API credentials using OAuth 2.0 authentication with a private key:

- Client ID
- Private Key ID
- Private Key
- Organization name
- Base URL

The provider is configured with the following scopes:

- okta.apps.manage
- okta.apps.read
- okta.groups.manage
- okta.groups.read
- okta.policies.manage
- okta.policies.read
- okta.profileMappings.manage
- okta.profileMappings.read

## Usage

```hcl
module "okta_saml_app" {
  source = "andrew-kemp-dahlberg/app/okta"
  version = "0.1.1"

  # Okta authentication
  client_id      = var.okta_client_id
  org_name       = "your-org"
  base_url       = "okta.com"
  private_key_id = var.okta_private_key_id
  private_key    = var.okta_private_key

  # Application basics
  name = "My SAML Application"

  # SAML settings
  saml_app_settings = {
    sso_url  = "https://app.example.com/sso/saml"
    audience = "https://app.example.com"
    logo     = filebase64("app_logo.png")
    
    # Optional settings
    attribute_statements = [
      {
        type        = "user"
        name        = "email"
        name_format = "basic"
        values      = ["user.email"]
      },
      {
        type         = "group"
        name         = "groups"
        name_format  = "basic"
        filter_value = ".*"
      }
    ]
  }

  # Admin notes for documentation
  admin_note = {
    saas_mgmt_name  = "Example App"
    accounting_name = "Example Inc"
    sso_enforced    = true
    lifecycle_automations = {
      provisioning = {
        type = "SCIM"
        link = ""
      }
      user_updates = {
        type = "SCIM"
        link = ""
      }
      deprovisioning = {
        type = "SCIM"
        link = ""
      }
    }
    service_accounts       = ["service@example.com"]
    app_owner              = "admin@example.com"
    last_access_audit_date = "2023-06-15"
    additional_notes       = "This is an example application"
  }

  # Application roles
  roles = [
    {
      role    = "User"
      profile = {}
    },
    {
      role    = "Admin"
      profile = {
        role = "admin"
      }
    }
  ]

  # Optional: Super admin role
  admin_role = {
    role = "superadmin"
  }

  # Optional: Device assurance policies
  device_assurance_policy_ids = {
    Mac     = "policy123"
    Windows = "policy456"
    iOS     = "policy789"
    Android = "policy012"
  }

  # Optional: Custom authentication policy rules
  authentication_policy_rules = [
    {
      name                        = "Managed Devices"
      factor_mode                 = "2FA"
      device_is_managed           = true
      re_authentication_frequency = "PT12H"
      constraints = [
        jsonencode({
          knowledge = { required = true }
          possession = {
            required           = true
            hardwareProtection = "REQUIRED"
          }
        })
      ]
    }
  ]
}
```

## Input Variables

### Required Variables

 Name  Description  Type  client_id  Okta Client ID  string  org_name  Okta organization name  string  base_url  Okta Base URL (e.g., okta.com)  string  private_key_id  Okta OAuth private key ID  string  private_key  Okta OAuth private key  string  name  Application label  string  admin_note  Administrative notes and metadata  object  saml_app_settings  SAML application configuration  object 

### Optional Variables

 Name  Description  Type  Default  authentication_policy_rules  Custom authentication policy rules  list(object)  null  roles  Role-based assignments  list(object)  [{role = "assignment", profile = {}}]  admin_role  Super admin role configuration  map(any)  {}  device_assurance_policy_ids  Device assurance policy IDs for different platforms  object  {} 

### Admin Note Structure

The `admin_note` variable captures important administrative metadata about the application:

```hcl
admin_note = {
  saas_mgmt_name  = string            # Name in SaaS management system
  accounting_name = string            # Name in accounting system
  sso_enforced    = bool              # Whether SSO is enforced
  lifecycle_automations = {
    provisioning = {
      type = string                   # One of: SCIM, HRIS, Okta Workflows fully automated, Okta workflows Zendesk, AWS, None
      link = string                   # Link to automation workflow (if applicable)
    }
    user_updates = {
      type = string                   # Same options as provisioning
      link = string
    }
    deprovisioning = {
      type = string                   # Same options as provisioning
      link = string
    }
  }
  service_accounts       = list(string) # List of service account emails
  app_owner              = string       # Email of application owner
  last_access_audit_date = string       # Date of last access audit (YYYY-MM-DD)
  additional_notes       = string       # Any additional notes
}
```

### SAML Application Settings

The `saml_app_settings` variable provides comprehensive configuration for the SAML application:

```hcl
saml_app_settings = {
  # Required fields
  sso_url  = string           # Single Sign-On URL
  audience = string           # SP Entity ID / Audience
  logo     = string           # Base64-encoded logo

  # Optional basic settings
  label             = string  # Application label (defaults to module name)
  preconfigured_app = string  # Preconfigured app name if using a template
  recipient         = string  # SAML Recipient (defaults to SSO URL)
  destination       = string  # SAML Destination (defaults to SSO URL)

  # Accessibility settings
  accessibility_error_redirect_url = string
  accessibility_login_redirect_url = string
  accessibility_self_service       = bool
  auto_submit_toolbar              = bool
  hide_ios                         = bool
  hide_web                         = bool
  default_relay_state              = string

  # Endpoint settings
  acs_endpoints             = list(string)
  single_logout_certificate = string
  single_logout_issuer      = string
  single_logout_url         = string

  # SAML protocol settings
  assertion_signed            = bool
  authn_context_class_ref     = string
  digest_algorithm            = string
  honor_force_authn           = bool
  idp_issuer                  = string
  request_compressed          = bool
  response_signed             = bool
  saml_signed_request_enabled = bool
  saml_version                = string
  signature_algorithm         = string
  sp_issuer                   = string
  subject_name_id_format      = string
  subject_name_id_template    = string

  # Certificate settings
  key_name        = string
  key_years_valid = number

  # User management settings
  user_name_template             = string
  user_name_template_push_status = string
  user_name_template_suffix      = string
  user_name_template_type        = string
  inline_hook_id                 = string

  # Application settings
  status              = string
  enduser_note        = string
  implicit_assignment = bool

  # Attribute statements
  attribute_statements = list(object({
    type         = string       # "user" or "group"
    name         = string       # Attribute name
    name_format  = string       # "basic", "uri reference", or "unspecified"
    filter_value = string       # For group type attributes
    values       = list(string) # For user type attributes
  }))
}
```

### Authentication Policy Rules

The `authentication_policy_rules` variable allows for custom authentication policy configuration:

```hcl
authentication_policy_rules = [
  {
    name                        = string
    access                      = string       # "ALLOW" or "DENY"
    factor_mode                 = string       # "1FA" or "2FA"
    type                        = string       # Usually "ASSURANCE"
    status                      = string       # "ACTIVE" or "INACTIVE"
    re_authentication_frequency = string       # Duration in ISO-8601 format
    custom_expression           = string       # Custom expression for rule
    network_includes            = list(string) # Network zones to include
    network_excludes            = list(string) # Network zones to exclude
    risk_score                  = string       # Risk score level
    inactivity_period           = string       # Inactivity period in ISO-8601
    network_connection          = string       # "ANYWHERE", "ON_NETWORK", etc.
    device_is_managed           = bool         # Whether device must be managed
    device_is_registered        = bool         # Whether device must be registered
    device_assurances_included  = list(string) # Device assurance policy IDs
    groups_included             = list(string) # Group IDs of groups to include
    groups_excluded             = list(string) # Group IDs of groups to exclude
    users_included              = list(string) # Users IDs of users to include
    users_excluded              = list(string) # Users IDs of users to exclude
    user_types_included         = list(string) # User types to include
    user_types_excluded         = list(string) # User types to exclude
    constraints                 = list(string) # JSON strings of constraints
    platform_include = list(object({          # Platforms to include
      os_type = string                        # OS type
      type    = string                        # Device type
    }))
  }
]
```

## Outputs

 Name  Description  saml_app  Created SAML application details  app_url  URL for the application  app_metadata  SAML application metadata  app_settings  SAML application settings  admin_note_details  Admin note details for the application  authentication_policy_info  Authentication policy information if configured  app_roles  Application roles configuration 

## Resources Created

This module creates the following resources:

1. **SAML Application** (`okta_app_saml.saml_app`): The main SAML application with all configured settings.

2. **Assignment Groups** (`okta_group.assignment_groups`): One group for each role defined in the `roles` variable, named according to the pattern `APP-ROLE-{APP_NAME}-{ROLE_NAME}`.

3. **Authentication Policy** (`okta_app_signon_policy.authentication_policy`): A sign-on policy specific to this application.

4. **Authentication Policy Rules** (`okta_app_signon_policy_rule.auth_policy_rules`): Rules defining the authentication requirements for different user groups and scenarios.

5. **Group Assignments** (`okta_app_group_assignments.main_app`): Assignments connecting the created groups to the application with the appropriate role profiles.

## Default Authentication Policy

If no custom authentication policy rules are provided, the module creates a default policy with three rules:

1. **Super Admin Authentication Policy Rule**:

- Requires 2FA with phishing-resistant authentication
- Requires managed and registered devices
- Applies to users in the first assignment group (typically admins)
- Re-authentication on every sign-in

2. **Supported Devices**:

- Requires 2FA with phishing-resistant authentication
- Requires registered devices
- Applies to all users except admins
- Re-authentication after 1 year (PT43800H)

3. **Unsupported Devices**:

- Requires 2FA
- Applies to all users except admins
- For Chromebooks and other non-standard devices
- Re-authentication after 1 year (PT43800H)

## Advanced Features

### Device Assurance

The module supports device assurance policies for different platforms (Mac, Windows, iOS, Android). When configured, these policies are integrated into the authentication rules to enforce device security requirements.

### Role-Based Access

The module creates dedicated groups for each role defined in the `roles` variable, allowing for granular control of user permissions within the application.

### Administrative Documentation

The `admin_note` structure embeds detailed documentation about the application directly in Okta, including:

- SaaS management information
- Lifecycle automation details
- Service account inventory
- Ownership and audit information

## Best Practices

1. **Use descriptive names**: Provide clear, descriptive names for your applications and roles.

2. **Document thoroughly**: Fill out the `admin_note` object completely to ensure proper documentation.

3. **Use device assurance**: When possible, configure device assurance policies to enforce security requirements.

4. **Limit admin access**: Create specific roles with minimal permissions necessary for each user group.

5. **Enforce strong authentication**: Configure appropriate authentication policies based on the sensitivity of the application.

## License

This module does not specify a license in the provided code.
