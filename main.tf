locals {
  roles = concat(
    var.admin_role != {} ? [{
      role    = "Super Admin"
      profile = var.admin_role
    }] : [],
    var.roles
  )

  profile             = [for role in local.roles : role.profile]
  app_group_names     = ["Not a department group"]
  push_group_names    = ["Not a department group"]
  mailing_group_names = ["Not a department group"]
  group_profile = [for p in local.profile : length(p) == 0 ?
    "No profile assigned" :
    replace(
      jsonencode(p),
      "/^{|}$/",
      ""
    )
  ]

  group_notes = [for p in local.profile : format(
    "Assigns the user to the %s with the following profile.\n%s\nGroup is managed by Terraform. Do not edit manually.",
    var.name,
    jsonencode(p)
  )]

  custom_attributes = [for index in range(length(local.roles)) : merge(
    { notes = local.group_notes[index] },
    { assignmentProfile = local.group_profile[index] },
    local.app_group_names != "" ? { applicationAssignments = local.app_group_names } : {},
    local.mailing_group_names != "" ? { mailingLists = local.mailing_group_names } : {},
    local.push_group_names != "" ? { pushGroups = local.push_group_names } : {}
  )]
}

resource "okta_group" "assignment_groups" {
  count                     = length(local.roles)
  name                      = "APP-ROLE-${upper(var.name)}-${upper(local.roles[count.index].role)}"
  description               = "Group assigns users to ${var.name} with the role of ${local.roles[count.index].role}"
  custom_profile_attributes = jsonencode(local.custom_attributes[count.index])
}

locals {
  admin_group_description = var.admin_role == {} ? "Group for ${var.name} super admins. Admin assignment is not automatic and must be assigned within the app" : "Group for ${var.name} super admins. Privileges are automatically assigned from this group" 
}

locals {
  policy_description = var.authentication_policy_rules == null ? "Authentication Policy for ${var.name}. It is the default policy set by Terraform." : "Authentication Policy for ${var.name}. It is a custom policy set through the terraform app module"
}

resource "okta_app_signon_policy" "authentication_policy" {
  description = local.policy_description
  name        = "${var.name } Authentication Policy"
  catch_all   = false
}

locals {
  device_assurances = compact(
    concat(
      [try(var.device_assurance_policy_ids.Mac, null)],
      [try(var.device_assurance_policy_ids.Windows, null)],
      [try(var.device_assurance_policy_ids.iOS, null)],
      [try(var.device_assurance_policy_ids.Android, null)]
    )
    ) == [] ? null : compact(
    concat(
      [try(var.device_assurance_policy_ids.Mac, null)],
      [try(var.device_assurance_policy_ids.Windows, null)],
      [try(var.device_assurance_policy_ids.iOS, null)],
      [try(var.device_assurance_policy_ids.Android, null)]
    )
  )


  default_auth_rules = [
    # Rule 1: Super Admin Authentication Policy Rule (not shown in your example but mentioned earlier)
    {
      name                        = "Super Admin Authentication Policy Rule"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      status                      = "ACTIVE"
      re_authentication_frequency = "PT0S"
      priority                    = 1
      custom_expression           = null
      network_includes            = null
      network_excludes            = null
      risk_score                  = ""
      inactivity_period           = "PT1H"
      network_connection          = "ANYWHERE"
      device_is_managed           = true
      device_is_registered        = true
      device_assurances_included  = local.device_assurances
      groups_included             = [okta_group.assignment_groups[0].id]
      groups_excluded             = []
      users_included              = []
      users_excluded              = []
      user_types_included         = []
      user_types_excluded         = []
      constraints                 = [jsonencode({
        knowledge = { required = true }
        possession = {
          authenticationMethods = [{ key = "okta_verify", method = "signed_nonce" }]
          required           = true
          hardwareProtection = "REQUIRED"
          phishingResistant  = "REQUIRED"
        }
      })]
      platform_include            = []  
    },

    # Rule 2: Supported Devices
    {
      name                        = "Supported Devices"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      status                      = "ACTIVE"
      re_authentication_frequency = "PT0S"
      priority                    = 2  
      custom_expression           = null
      network_includes            = null
      network_excludes            = null
      risk_score                  = ""
      inactivity_period           = "PT43800H"
      network_connection          = "ANYWHERE"
      device_is_managed           = null
      device_is_registered        = true
      device_assurances_included  = local.device_assurances
      groups_included             = []
      groups_excluded             = [okta_group.assignment_groups[0].id]
      users_included              = []
      users_excluded              = []
      user_types_included         = []
      user_types_excluded         = []
      constraints                 = [jsonencode({
        knowledge = { required = true }
        possession = {
          authenticationMethods = [{ key = "okta_verify", method = "signed_nonce" }]
          required           = true
          hardwareProtection = "REQUIRED"
          phishingResistant  = "REQUIRED"
        }
      })]
      platform_include            = [] 
    },

    # Rule 3: Unsupported Devices
    {
      name                        = "Unsupported Devices"
      access                      = "ALLOW"
      factor_mode                 = "2FA"
      type                        = "ASSURANCE"
      status                      = "ACTIVE"
      re_authentication_frequency = "PT43800H"
      priority                    = 3
      custom_expression           = null
      network_includes            = null
      network_excludes            = null
      risk_score                  = ""
      inactivity_period           = ""
      network_connection          = "ANYWHERE"
      device_is_managed           = null
      device_is_registered        = null
      device_assurances_included  = null
      groups_included             = []
      groups_excluded             = [okta_group.assignment_groups[0].id]
      users_included              = []
      users_excluded              = []
      user_types_included         = []
      user_types_excluded         = []
      constraints                 = [jsonencode({
        knowledge = {
          reauthenticateIn = "PT43800H"
          types            = ["password"]
          required         = true
        }
        possession = {
          required           = true
          hardwareProtection = "REQUIRED"
        }
      })]
      platform_include = [
        { os_type = "CHROMEOS", type = "DESKTOP" },
        { os_type = "OTHER", type = "DESKTOP" },
        { os_type = "OTHER", type = "MOBILE" }
      ]
    }
  ]

  auth_rules = var.authentication_policy_rules == null ? local.default_auth_rules : var.authentication_policy_rules
}

resource "okta_app_signon_policy_rule" "auth_policy_rules" {
  count                       = length(local.auth_rules)
  policy_id                   = okta_app_signon_policy.authentication_policy.id
  name                        = local.auth_rules[count.index].name
  access                      = try(local.auth_rules[count.index].access, "ALLOW")
  factor_mode                 = try(local.auth_rules[count.index].factor_mode, "2FA")
  type                        = try(local.auth_rules[count.index].type, "ASSURANCE")
  re_authentication_frequency = try(local.auth_rules[count.index].re_authentication_frequency, "PT0S")
  constraints                 = try(local.auth_rules[count.index].constraints, [])
  priority                    = try(local.auth_rules[count.index].priority, count.index + 1)
  status                      = try(local.auth_rules[count.index].status, "ACTIVE")
  custom_expression           = try(local.auth_rules[count.index].custom_expression, null) 
   inactivity_period           = try(local.auth_rules[count.index].inactivity_period, "")
  network_connection          = try(local.auth_rules[count.index].network_connection, "ANYWHERE")
  network_includes            = try(local.auth_rules[count.index].network_includes, null)   
  network_excludes            = try(local.auth_rules[count.index].network_excludes, null)   
  risk_score                  = try(local.auth_rules[count.index].risk_score, "")
  device_is_managed          = try(local.auth_rules[count.index].device_is_managed, null)
  device_is_registered       = try(local.auth_rules[count.index].device_is_registered, null)
  device_assurances_included = try(local.auth_rules[count.index].device_assurances_included, [])
  groups_included     = try(local.auth_rules[count.index].groups_included, [])
  groups_excluded     = try(local.auth_rules[count.index].groups_excluded, [])
  users_included      = try(local.auth_rules[count.index].users_included, [])
  users_excluded      = try(local.auth_rules[count.index].users_excluded, [])
  user_types_included = try(local.auth_rules[count.index].user_types_included, [])
  user_types_excluded = try(local.auth_rules[count.index].user_types_excluded, [])

  dynamic "platform_include" {
    for_each = try(local.auth_rules[count.index].platform_include, [])
    content {
      os_type = platform_include.value.os_type
      type    = platform_include.value.type
    }
  }
}


locals {
  # Process each SAML app configuration to add computed locals
  saml_apps_with_locals = [
    for idx, app in var.saml_app_settings : merge(app, {
      # Computed fields for each app
      _recipient = app.recipient == null ? app.sso_url : app.recipient
      _destination = app.destination == null ? app.sso_url : app.destination
      
      _attribute_statements = app.attribute_statements == null ? [] : [
        for attr in app.attribute_statements : {
          name = attr.name
          namespace = lookup({
            "basic"         = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
            "uri reference" = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "unspecified"   = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
          }, attr.name_format, "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
          type         = attr.type == "user" ? "EXPRESSION" : "GROUP"
          filter_type  = attr.type == "group" ? "REGEX" : null
          filter_value = attr.type == "group" ? attr.filter_value : null
          values       = attr.type == "user" ? attr.values : []
        }
      ]
      
      _label = "SAML App - ${app.name}"
      
      _admin_note = {
        name = try(app.admin_note.saas_mgmt_name, "")
        sso  = try(app.admin_note.sso_enforced, false)
        auto = try(distinct([
          app.admin_note.lifecycle_automations.provisioning.type,
          app.admin_note.lifecycle_automations.user_updates.type,
          app.admin_note.lifecycle_automations.deprovisioning.type
        ]), ["None"])
        owner = try(app.admin_note.app_owner, "")
        audit = try(app.admin_note.last_access_audit_date, "")
      }
    })
  ]
  
  # Convert list to map with index as key for easier reference in resources
  saml_apps_map = { for idx, app in local.saml_apps_with_locals : idx => app }
}

resource "okta_app_saml" "saml_apps" {
  for_each = local.saml_apps_map

  # Required basic settings
  label    = each.value._label
  sso_url  = each.value.sso_url
  audience = each.value.audience
  
  # Optional basic settings with computed defaults
  recipient   = each.value._recipient
  destination = each.value._destination
  
  # Accessibility settings
  accessibility_error_redirect_url = each.value.accessibility_error_redirect_url
  accessibility_login_redirect_url = each.value.accessibility_login_redirect_url
  accessibility_self_service       = each.value.accessibility_self_service
  auto_submit_toolbar              = each.value.auto_submit_toolbar
  hide_ios                         = each.value.hide_ios
  hide_web                         = each.value.hide_web
  default_relay_state              = each.value.default_relay_state
  
  # Endpoint settings
  acs_endpoints           = each.value.acs_endpoints
  single_logout_certificate = each.value.single_logout_certificate
  single_logout_issuer    = each.value.single_logout_issuer
  single_logout_url       = each.value.single_logout_url
  
  # SAML protocol settings
  assertion_signed           = each.value.assertion_signed
  authn_context_class_ref    = each.value.authn_context_class_ref
  digest_algorithm           = each.value.digest_algorithm
  honor_force_authn          = each.value.honor_force_authn
  idp_issuer                 = each.value.idp_issuer
  request_compressed         = each.value.request_compressed
  response_signed            = each.value.response_signed
  saml_signed_request_enabled = each.value.saml_signed_request_enabled
  saml_version               = each.value.saml_version
  signature_algorithm        = each.value.signature_algorithm
  sp_issuer                  = each.value.sp_issuer
  subject_name_id_format     = each.value.subject_name_id_format
  subject_name_id_template   = each.value.subject_name_id_template
  
  # Certificate settings
  key_name        = each.value.key_name
  key_years_valid = each.value.key_years_valid
  
  # User management settings
  user_name_template           = each.value.user_name_template
  user_name_template_push_status = each.value.user_name_template_push_status
  user_name_template_suffix    = each.value.user_name_template_suffix
  user_name_template_type      = each.value.user_name_template_type
  inline_hook_id               = each.value.inline_hook_id
  
  # Application settings
  status              = each.value.status
  enduser_note        = each.value.enduser_note
  implicit_assignment = each.value.implicit_assignment
  
  # Dynamic attribute statements using the processed local values
  dynamic "attribute_statements" {
    for_each = each.value._attribute_statements
    
    content {
      name       = attribute_statements.value.name
      namespace  = attribute_statements.value.namespace
      type       = attribute_statements.value.type
      filter_type = attribute_statements.value.filter_type
      filter_value = attribute_statements.value.filter_value
      values     = attribute_statements.value.values
    }
  }
}


resource "okta_app_group_assignments" "main_app" {

  for_each = okta_app_saml.saml_apps
  app_id = okta_app_saml.saml_apps[*].id
  dynamic "group" {
    for_each = okta_group.assignment_groups[*].id
    iterator = group_id
    content {
      id       = group_id.value
      profile  = jsonencode(local.roles[group_id.key].profile)
      priority = tonumber(group_id.key) + 1
    }
  }
}

