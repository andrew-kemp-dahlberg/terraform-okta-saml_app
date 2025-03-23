# Okta SAML Application Module

This Terraform module creates and configures an Okta SAML application with role-based access, attribute statements, and schema customization.

## Features

- Creates a SAML application in Okta with comprehensive configuration options
- Supports both preconfigured and custom SAML applications
- Creates role-based assignment groups for application access
- Configures user and group attribute statements for SAML assertions
- Customizes application schema with base and custom properties
- Manages authentication policies and app visibility

## Usage

```hcl
module "okta_saml_app" {
  source = "path/to/module"

  name = "MyApplication"
  
  environment = {
    org_name       = "your-org"
    base_url       = "okta.com"
    client_id      = "your-client-id"
    private_key_id = "your-private-key-id"
    private_key    = "your-private-key"
    authentication_policy_ids = {
      high   = "policy-id-1"
      medium = "policy-id-2"
      low    = "policy-id-3"
    }
    device_assurance_policy_ids = {
      Mac     = "policy-id-4"
      Windows = "policy-id-5"
      iOS     = "policy-id-6"
      Android = "policy-id-7"
    }
  }
  
  admin_note = {
    saas_mgmt_name  = "My Application"
    accounting_name = "MyApp"
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
    last_access_audit_date = "2023-01-01"
    additional_notes       = "Additional notes about the application"
  }
  
  saml_app = {
    sso_url    = "https://example.com/sso/saml"
    audience   = "https://example.com"
    logo       = "https://example.com/logo.png"
    label      = "My Application"
    status     = "ACTIVE"
    
    user_attribute_statements = [
      {
        name        = "email"
        name_format = "basic"
        values      = ["user.email"]
      }
    ]
    
    group_attribute_statements = {
      name        = "groups"
      name_format = "basic"
    }
  }
  
  roles = [
    {
      name                = "Admin"
      attribute_statement = true
      profile             = {
        role = "admin"
      }
    },
    {
      name                = "User"
      attribute_statement = true
      profile             = {
        role = "user"
      }
    }
  ]
  
  authentication_policy = "high"
  
  base_schema = [
    {
      index       = "userName"
      title       = "Username"
      type        = "string"
      required    = true
      permissions = "READ_WRITE"
    }
  ]
  
  custom_schema = [
    {
      index       = "customField"
      title       = "Custom Field"
      type        = "string"
      description = "A custom field for the application"
      scope       = "NONE"
      permissions = "READ_WRITE"
    }
  ]
}
```

## Inputs

### Required Inputs

 Name  Description  Type  name  Application label  string  environment  Information to authenticate with Okta Provider  object  admin_note  Administrative notes and metadata about the application  object 

### Optional Inputs

 Name  Description  Type  Default  saml_app  SAML application configuration  object  null  roles  Role-based assignments for groups  list(object)  See variables.tf  authentication_policy  Authentication policy level or ID  string  "high"  base_schema  Application user base schema properties  list(object)  custom_schema  Custom schema properties for the Okta app  list(object) 

## Outputs

 Name  Description  saml_app  Created SAML application details  app_url  URL for the application  app_metadata  SAML application metadata  app_settings  SAML application settings  admin_note_details  Admin note details for the application  authentication_policy_info  Authentication policy information if configured  app_roles  Application roles configuration 

## SAML Application Configuration

The module supports extensive configuration options for SAML applications through the `saml_app` variable. This includes:

- Basic settings (SSO URL, audience, logo)
- Accessibility settings
- Endpoint configurations
- SAML protocol settings
- Certificate management
- User management settings
- Attribute statements

## Role-Based Access

The module creates Okta groups for role-based access to the application. Each role can:

- Be included in SAML attribute statements
- Have a custom profile for application assignments
- Be used for automatic privilege assignment within the application

## Schema Customization

The module allows customization of both base and custom schema properties for the application, enabling:

- Custom field definitions
- Validation rules
- Permission settings
- Master source configuration

## License

This module is licensed under the MIT License.