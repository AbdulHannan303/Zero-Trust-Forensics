package ztforensics.authz

# ─────────────────────────────────────────────────────────────────────────────
# ZTForensics — Zero Trust Authorization Policy (OPA Rego)
#
# This policy evaluates every access request and returns:
#   allow  — true if access is granted, false otherwise
#   reason — human-readable string explaining the decision
#
# Input fields expected from the API gateway:
#   input.user        — authenticated username
#   input.resource    — target resource path
#   input.action      — requested operation (read/write/delete)
#   input.risk_score  — integer 0-100 from the risk scorer
#   input.hour        — UTC hour of the request (0-23)
#   input.ip_address  — source IP address
# ─────────────────────────────────────────────────────────────────────────────

default allow := false

# ── Grant access when risk is low AND the resource access is valid ───────────
allow {
    input.risk_score < 50
    valid_resource_access
}

# ── Deny reason helpers ───────────────────────────────────────────────────────

# Critical risk threshold
reason := "HIGH_RISK_SCORE: Risk score exceeds safety threshold (>=70)" {
    input.risk_score >= 70
}

# Warning zone — medium risk
reason := "MEDIUM_RISK: Risk score in warning zone (50-69), requires review" {
    input.risk_score >= 50
    input.risk_score < 70
}

# Before-hours access (midnight – 5 AM)
reason := "BEFORE_HOURS: Access attempted before business hours (06:00)" {
    input.hour < 6
}

# After-hours access (11 PM – midnight)
reason := "AFTER_HOURS: Access attempted after business hours (22:00)" {
    input.hour > 22
}

# Unauthorized resource
reason := "UNAUTHORIZED_RESOURCE: User does not have access to this resource" {
    not valid_resource_access
}

# Success reason (only set when allow is true)
reason := "ALLOWED: All policy checks passed" {
    allow
}

# ── Resource access rules ─────────────────────────────────────────────────────

# Admins can access everything
valid_resource_access {
    input.user == "admin"
}

# Non-admin users can access any non-admin resource
valid_resource_access {
    not startswith(input.resource, "/api/admin")
}
