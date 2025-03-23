# Okta SAML Application Module

This Terraform module configures a SAML application in Okta with comprehensive customization options for authentication, attribute mapping, and user role management.

## Features

- Create and configure SAML applications in Okta
- Support for both custom and preconfigured Okta app integrations
- Flexible role-based access control with automatic group creation
- User and group attribute statement mapping
- Authentication policy configuration
- Detailed admin notes and documentation within Okta

## Prerequisites

- Terraform 1.0+
- Okta provider 4.15.0+
- Appropriate Okta API credentials with the following scopes:
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
  source = "path/to/module"

  name = "My SAML Application"
  
  environment = {
    org_name       = "your-okta-org"
    base_url       = "okta.com"
    client_id      = "your-client-id"
    private_key_id = "your-private-key-id"
    private_key    = "your-private-key"
    authentication_policy_ids = {
      high   = "policy-id-high"
      medium = "policy-id-medium"
      low    = "policy-id-low"
    }
    device_assurance_policy_ids = {
      Mac     = "policy-id-mac"
      Windows = "policy-id-windows"
      iOS     = "policy-id-ios"
      Android = "policy-id-android"
    }
  }

  admin_note = {
    saas_mgmt_name  = "Application Name"
    accounting_name = "Accounting Label"
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
    app_owner              = "owner@example.com"
    last_access_audit_date = "2023-05-01"
    additional_notes       = "Additional configuration details"
  }

  saml_app = {
    sso_url    = "https://example.com/sso/saml"
    audience   = "https://example.com"
    logo       = filebase64("path/to/logo.png")
    
    user_attribute_statements = [
      {
        name        = "email"
        name_format = "basic"
        values      = ["user.email"]
      },
      {
        name        = "firstName"
        name_format = "basic"
        values      = ["user.firstName"]
      }
    ]
    
    group_attribute_statements = {
      name = "groups"
      name_format = "basic"
    }
  }

  roles = [
    {
      name                = "Standard User"
      attribute_statement = true
      profile             = { role = "standard" }
    },
    {
      name                = "Manager"
      attribute_statement = true
      profile             = { role = "manager" }
    }
  ]

  admin_role = {
    attribute_statement = true
    profile             = { role = "admin" }
  }

  authentication_policy = "high"
}
```

## Input Variables

### Required Variables

 Name  Description  `environment`  Okta environment configuration with authentication details  `name`  Application name/label  `admin_note`  Administrative notes and configuration details 

### Optional Variables

 Name  Description  Default  `saml_app`  SAML application configuration  `null`  `authentication_policy`  Authentication policy level or ID  `"high"`  `roles`  List of application roles to create  `[{name = "assignment", profile = {}, attribute_statement = false, claim = false}]`  `admin_role`  Super admin role configuration  `{profile = {}, attribute_statement = false, claim = false}` 

## Outputs

 Name  Description  `saml_app`  Basic information about the created SAML application  `app_url`  URL for the application  `app_metadata`  SAML application metadata including entity ID and certificate  `app_settings`  Core SAML application settings  `admin_note_details`  Admin note details for the application  `authentication_policy_info`  Authentication policy information if configured  `app_roles`  Application roles configuration 

## Role-Based Access Control

This module automatically creates Okta groups for each role defined, following the naming convention:

```javascript
APP-ROLE-[APP_NAME]-[ROLE_NAME]
```

For example, with an application named "Salesforce" and roles "Admin" and "User", it will create:

- APP-ROLE-SALESFORCE-ADMIN
- APP-ROLE-SALESFORCE-USER

## SAML Attribute Statements

The module supports both user and group attribute statements:

- User attribute statements map Okta user attributes to SAML assertions
- Group attribute statements allow role-based claims based on group membership

## License

This module is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).