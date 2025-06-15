from django.core.management import call_command

from TeacherAssist import settings
from tenants.models import Tenant, Domain
from django.test.runner import DiscoverRunner


class TenantTestRunner(DiscoverRunner):
    """
    1) Runs the normal test database setup (migrates public schema).
    2) Creates a dummy tenant + its Domain.
    3) Calls `migrate_schemas --schema_name=test_tenant` to build out the
       tenant schema (including token_blacklist tables).
    """

    def setup_databases(self, **kwargs):
        # 1) public schema migrations & test DB setup
        old_config = super().setup_databases(**kwargs)

        # 2) Create a dummy tenant
        dummy, _ = Tenant.objects.get_or_create(
            schema_name="test_tenant",
            defaults={
                "name": "Test Tenant",
                # auto_create_schema=True on your model will
                # cause django-tenants to generate the schema
                "auto_create_schema": True,
            },
        )

        Domain.objects.get_or_create(
            tenant=dummy,
            domain=f"test_tenant.{settings.TENANT_SUBDOMAIN_BASE}",
            defaults={"is_primary": True},
        )

        # 3) Run tenant migrations for that schema
        call_command(
            "migrate_schemas",
            schema_name="test_tenant",
            interactive=False,
            verbosity=0,
        )

        return old_config