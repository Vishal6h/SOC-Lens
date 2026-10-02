"""Explicit default-deny SOCLens role and permission model."""

ROLES = ("ADMIN", "SUPERVISOR", "ASSESSOR", "REVIEWER", "AUDITOR")

PERMISSIONS = frozenset({
    "assessment.read", "assessment.create", "assessment.run", "assessment.export",
    "incident.read", "finding.read", "history.read",
    "evidence.import", "evidence.delete_staged",
    "report.read", "report.export", "policy.read",
    "security.user.read", "security.user.create", "security.user.update",
    "security.user.disable", "security.audit.read",
    "operations.status.read", "operations.backup", "operations.restore",
})

_READ = {
    "assessment.read", "incident.read", "finding.read", "report.read", "policy.read",
    "operations.status.read",
}

ROLE_PERMISSIONS = {
    "ADMIN": PERMISSIONS,
    "SUPERVISOR": frozenset(_READ | {
        "assessment.create", "assessment.run", "assessment.export", "history.read",
        "evidence.import", "evidence.delete_staged", "report.export",
    }),
    "ASSESSOR": frozenset(_READ | {
        "assessment.create", "assessment.run", "evidence.import", "evidence.delete_staged",
    }),
    "REVIEWER": frozenset(_READ | {"history.read"}),
    "AUDITOR": frozenset(_READ | {
        "assessment.export", "history.read", "report.export", "security.audit.read",
    }),
}


def permissions_for(role):
    """Return an immutable permission set; unknown roles receive no authority."""
    return ROLE_PERMISSIONS.get(role, frozenset())


def allowed(role, permission):
    return permission in PERMISSIONS and permission in permissions_for(role)
