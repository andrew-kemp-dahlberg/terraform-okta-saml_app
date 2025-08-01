# Okta SAML Application Module

This Terraform module creates and configures an Okta SAML application with role-based access, attribute statements, and schema customization.

## Features

- Creates a SAML application in Okta with comprehensive configuration options
- Supports both preconfigured and custom SAML applications
- Creates role-based assignment groups for application access
- Configures user and group attribute statements for SAML assertions
- Customizes application schema with base and custom properties
- Manages profile mappings between Okta and the application
- Handles authentication policies and app visibility
- Includes validation and precondition checks for safe deployment

## Usage

### Basic Example

```hcl
module "okta_app" {
  source = "path/to/module"
  
  name = "My Application"
  
  admin_note = {
    saas_mgmt_name         = "My Application"
    accounting_name        = "MyApp"
    sso_enforced          = true
    service_accounts      = ["service@example.com"]
    app_owner             = "owner@example.com"
    last_access_audit_date = "2023-01-01"
    additional_notes      = "Additional notes about the application"
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
      name                = "admin"
      attribute_statement = true
      profile             = {
        role = "admin"
      }
    },
    {
      name                = "user"
      attribute_statement = true
      profile             = {
        role = "user"
      }
    }
  ]
  
  authentication_policy = "high"
}
```

### Advanced Example with Custom Schema

```hcl
module "okta_app" {
  source = "path/to/module"
  
  name = "Advanced Application"
  
  admin_note = {
    saas_mgmt_name         = "Advanced Application"
    accounting_name        = "AdvApp"
    sso_enforced          = true
    service_accounts      = ["service@example.com"]
    app_owner             = "owner@example.com"
    last_access_audit_date = "2024-01-01"
  }
  
  saml_app = {
    sso_url                = "https://app.example.com/sso/saml"
    audience              = "https://app.example.com"
    logo                  = "https://app.example.com/logo.png"
    assertion_signed      = true
    response_signed       = true
    signature_algorithm   = "RSA_SHA256"
    digest_algorithm      = "SHA256"
    
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
  }
  
  # Custom base schema configuration
  base_schema = [
    {
      id          = "userName"
      title       = "Username"
      type        = "string"
      required    = true
      permissions = "READ_ONLY"
    }
  ]
  
  # Custom schema properties
  custom_schema = [
    {
      id          = "department"
      title       = "Department"
      type        = "string"
      description = "User's department"
      required    = false
      permissions = "READ_WRITE"
    },
    {
      id          = "employeeId"
      title       = "Employee ID"
      type        = "string"
      description = "Unique employee identifier"
      required    = true
      permissions = "READ_ONLY"
      unique      = "UNIQUE_VALIDATED"
    }
  ]
  
  # Profile mappings
  profile_mappings = {
    to_app = [
      {
        id         = "department"
        expression = "user.department"
      },
      {
        id         = "employeeId"
        expression = "user.employeeNumber"
      }
    ]
    to_okta = []
  }
  
  roles = [
    {
      name                = "admin"
      attribute_statement = true
      profile = {
        role        = "admin"
        permissions = "full"
      }
    },
    {
      name                = "manager"
      attribute_statement = true
      profile = {
        role        = "manager"
        permissions = "limited"
      }
    },
    {
      name                = "employee"
      attribute_statement = false
      profile = {}
    }
  ]
}
```

## Variables

### Required Variables

| Name | Description | Type |
|------|-------------|------|
| `name` | Application label/name | `string` |
| `admin_note` | Administrative notes and metadata about the application | `object` |

### Optional Variables

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `saml_app` | SAML application configuration object | `object` | `null` |
| `roles` | Role-based assignments for groups | `list(object)` | Single "assignment" role |
| `authentication_policy` | Authentication policy level ("low", "medium", "high") or policy ID | `string` | `"high"` |
| `base_schema` | Base schema properties for the application | `list(object)` | Default username schema |
| `custom_schema` | Custom schema properties for the application | `list(object)` | `[]` |
| `profile_mappings` | Profile mappings between Okta and the application | `object` | Empty mappings |

### Admin Note Structure

```hcl
admin_note = {
  saas_mgmt_name         = string  # Required: Application name for SaaS management
  accounting_name        = string  # Required: Application name for accounting
  sso_enforced          = bool     # Required: Whether SSO is enforced
  service_accounts      = list(string)  # Required: List of service account emails
  app_owner             = string   # Required: Application owner email
  last_access_audit_date = string  # Required: Last audit date (YYYY-MM-DD format)
  additional_notes      = string   # Optional: Additional notes
}
```

### SAML App Configuration

The `saml_app` variable supports extensive SAML configuration options. For custom applications (not using `preconfigured_app`), you must provide:

- `sso_url`: Single Sign-On URL
- `audience`: Audience URI
- `logo`: Logo URL

All other SAML settings have sensible defaults but can be overridden as needed.

### Schema Configuration

- **Base Schema**: Modify core Okta user profile properties for the application
- **Custom Schema**: Add custom fields specific to the application
- **Profile Mappings**: Map data between Okta user profiles and application profiles

## Outputs

| Name | Description |
|------|-------------|
| `saml_app` | SAML application details (id, label, status, sign-on mode, entity ID) |
| `app_url` | Application embed URL |
| `app_settings` | SAML settings (SSO URL, audience, subject format) |
| `admin_note_details` | Admin configuration details |
| `app_roles` | Application roles configuration |
| `features` | Application features (primarily SCIM) |
| `schema_transformation_status` | Status of schema transformation |
| `existing_app_check` | Details of any existing app with the same label |

## Role-Based Access

The module creates Okta groups for role-based access to the application. Each role:

- Creates a group with naming pattern: `APP-ROLE-{UPPERCASE_APP_NAME}-{UPPERCASE_ROLE_NAME}`
- Can be included in SAML attribute statements (when `attribute_statement = true`)
- Can have a custom profile for application assignments
- Supports automatic privilege assignment within the application

### Role Configuration

```hcl
roles = [
  {
    name                = "admin"           # Role name (alphanumeric, hyphens, underscores only)
    attribute_statement = true              # Include in SAML group attribute statements
    profile            = {                  # Custom profile for app assignments
      role = "administrator"
      level = "full"
    }
  }
]
```

## Schema Customization

### Base Schema Properties

Modify core Okta properties for the application:

```hcl
base_schema = [
  {
    id          = "userName"                # Property ID
    title       = "Username"               # Display title
    type        = "string"                  # Data type
    master      = "PROFILE_MASTER"          # Master source
    permissions = "READ_ONLY"               # Permission level
    required    = true                      # Required field
    user_type   = "default"                 # User type
    pattern     = null                      # Validation pattern
  }
]
```

### Custom Schema Properties

Add application-specific fields:

```hcl
custom_schema = [
  {
    id                 = "department"           # Property ID
    title              = "Department"          # Display title
    type               = "string"              # Data type
    description        = "User department"     # Description
    master             = "PROFILE_MASTER"      # Master source
    permissions        = "READ_WRITE"          # Permission level
    required           = false                 # Required field
    unique             = "NOT_UNIQUE"          # Uniqueness constraint
    max_length         = 50                    # Maximum length
    enum               = ["IT", "HR", "Sales"] # Allowed values
  }
]
```

### Profile Mappings

Map data between Okta and the application:

```hcl
profile_mappings = {
  to_app = [
    {
      id          = "customField"
      expression  = "user.department"
      push_status = "PUSH"
    }
  ]
  to_okta = [
    {
      id          = "department"
      expression  = "appuser.customField"
      push_status = "PUSH"
    }
  ]
}
```

## Validation and Safety Features

The module includes comprehensive validation:

- **Email validation** for app owners and service accounts
- **Date format validation** for audit dates
- **SAML configuration validation** for algorithms, formats, and URLs
- **Schema validation** for types, permissions, and constraints
- **Precondition checks** to prevent conflicts with existing applications

## Best Practices

1. **Use descriptive role names** that reflect actual application permissions
2. **Set appropriate schema permissions** (READ_ONLY for sensitive data)
3. **Include service accounts** in admin_note for operational tracking
4. **Use unique validation** for critical identifiers in custom schema
5. **Test with preconfigured apps** before building custom SAML configurations
6. **Regular audit date updates** to track access reviews

## License

This module is licensed under the MIT License.