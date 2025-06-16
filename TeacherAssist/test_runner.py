from django.core.management import call_command
from django.db import connection

from TeacherAssist import settings
from tenants.models import Tenant, Domain
from django.test.runner import DiscoverRunner


class TenantTestRunner(DiscoverRunner):
    """
    1) Runs the normal test‐database setup (migrates public schema).
    2) Creates a dummy tenant + its Domain.
    3) Calls `migrate_schemas --schema_name=<TEST_TENANT_SCHEMA_NAME>`
       to build out the tenant schema.
    """

    def setup_databases(self, **kwargs):
        # 1) public‐schema migrations & test DB setup
        old_config = super().setup_databases(**kwargs)

        # 2) Create a dummy tenant/schema for tests
        test_schema = getattr(settings, "TEST_TENANT_SCHEMA_NAME", "test_tenant")
        tenant, _ = Tenant.objects.get_or_create(
            schema_name=test_schema,
            defaults={"name": test_schema.capitalize()},
        )

        # 2a) Attach a primary Domain to it
        Domain.objects.get_or_create(
            tenant=tenant,
            domain=f"{test_schema}.{settings.TENANT_SUBDOMAIN_BASE}",
            defaults={"is_primary": True},
        )

        # 3) Run tenant migrations (so all TENANT_APPS land there)
        call_command(
            "migrate_schemas",
            schema_name=test_schema,
            interactive=False,
            verbosity=0,
        )

        # 4) **IMPORTANT**: switch us back to the public schema
        #     so that any Tenant.objects.create(...) goes into public
        connection.set_schema_to_public()

        return old_config