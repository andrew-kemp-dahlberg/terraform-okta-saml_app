# Okta Application Module

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
module "okta_app" {
  source = "path/to/module"
  
  environment = {
    org_name  = "your-org"
    base_url  = "okta.com"
    api_token = "your-api-token"
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
    profile_mapping_settings = {
      delete_when_absent = false
      always_apply = false
    }
  }
  
  name = "My Application"
  
  admin_note = {
    saas_mgmt_name  = "My Application"
    accounting_name = "MyApp"
    sso_enforced    = true
    lifecycle = {
      enabled = false
      features = {
        create = false
        update = false
        deactivate = false
      }
      other_automation = null
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
  
  schema = [
    {
      id          = "userName"
      title       = "Username"
      type        = "string"
      required    = true
      permissions = "READ_ONLY"
    },
    {
      id           = "customField"
      custom_schema = true
      title        = "Custom Field"
      type         = "string"
      description  = "A custom field for the application"
      to_app_mapping = {
        expression = "user.email"
      }
    }
  ]
}
```

## Inputs

### Required Inputs

 Name  Description  Type  environment  Information to authenticate with Okta Provider  object  name  Application label  string  admin_note  Administrative notes and metadata about the application  object 

### Optional Inputs

 Name  Description  Type  Default  saml_app  SAML application configuration  object  null  roles  Role-based assignments for groups  list(object)  See variables.tf  authentication_policy  Authentication policy level or ID  string  "high"  schema  Schema configuration and profile mappings  list(object)  Default username schema 

## Outputs

 Name  Description  saml_app  SAML application details (id, label, status, sign-on mode, entity ID)  app_url  Application embed URL  app_settings  SAML settings (SSO URL, audience, subject format)  admin_note_details  Admin configuration (management info, owner, lifecycle settings)  app_roles  Application roles configuration  features  Application features (primarily SCIM)  schema_transformation_status  Status of schema transformation 

## SAML Application Configuration

The module supports extensive configuration options for SAML applications through the `saml_app` variable, with all properties defaulting to `null` to allow for preconfigured app templates. When using a custom application (not preconfigured), you must provide at minimum:

- `sso_url`: The SSO URL for the application
- `audience`: The audience URI for the application
- `logo`: URL to the application logo

For custom applications, the module applies sensible defaults for all SAML settings while allowing you to override any specific setting as needed.

## Role-Based Access

The module creates Okta groups for role-based access to the application. Each role can:

- Be included in SAML attribute statements (when `attribute_statement = true`)
- Have a custom profile for application assignments
- Be used for automatic privilege assignment within the application

Groups are created with the naming pattern `APP-ROLE-{APP_NAME}-{ROLE_NAME}`.

## Schema Customization

The module allows customization of both base and custom schema properties for the application, enabling:

- Custom field definitions
- Validation rules
- Permission settings
- Master source configuration
- Profile mappings to and from Okta

## License

This module is licensed under the MIT License.