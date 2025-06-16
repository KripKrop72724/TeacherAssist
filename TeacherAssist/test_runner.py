from django.core.management import call_command

from TeacherAssist import settings
from tenants.models import Tenant, Domain
from django.test.runner import DiscoverRunner


class TenantTestRunner(DiscoverRunner):
    """
    1. Runs the normal test‐database setup (migrates public schema).
    2. Creates a dummy tenant + its Domain.
    3. Calls `migrate_schemas --schema_name=<TEST_SCHEMA>` so that
       token_blacklist (and all TENANT_APPS) are migrated there.
    """

    def setup_databases(self, **kwargs):
        # 1) public schema migrations & test DB setup
        old_config = super().setup_databases(**kwargs)

        # 2) Create a dummy tenant/schema for tests
        test_schema = getattr(settings, "TEST_TENANT_SCHEMA_NAME", "test_tenant")
        dummy, _ = Tenant.objects.get_or_create(
            schema_name=test_schema,
            defaults={"name": test_schema.capitalize()},
        )

        Domain.objects.get_or_create(
            tenant=dummy,
            domain=f"{test_schema}.{settings.TENANT_SUBDOMAIN_BASE}",
            defaults={"is_primary": True},
        )

        # 3) Run tenant migrations for that schema (includes token_blacklist)
        call_command(
            "migrate_schemas",
            schema_name=getattr(settings, "PUBLIC_SCHEMA_NAME", "public"),
            interactive=False,
            verbosity=0,
        )

        return old_config