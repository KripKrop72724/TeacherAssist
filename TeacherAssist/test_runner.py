# test_runner.py

from django.test.runner import DiscoverRunner
from django.core.management import call_command

class TenantTestRunner(DiscoverRunner):
    """
    Runs the standard test database setup, then applies:
      - migrate_schemas --shared
      - migrate_schemas
    so that all SHARED_APPS (incl. token_blacklist) exist in public,
    and all TENANT_APPS (incl. token_blacklist too) exist in each schema.
    """

    def setup_databases(self, **kwargs):
        # 1) Let Django set up the test DB for the public schema
        result = super().setup_databases(**kwargs)

        # 2) Apply shared apps to the public schema
        call_command("migrate_schemas", "--shared", verbosity=0)

        # 3) Apply all apps to each tenant schema
        call_command("migrate_schemas", verbosity=0)

        return result
