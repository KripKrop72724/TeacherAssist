# TeacherAssist/test_runner.py
from django.test.runner import DiscoverRunner
from django.core.management import call_command

class TenantTestRunner(DiscoverRunner):
    """
    Extends the default DiscoverRunner to also run
    `migrate_schemas` on both shared and tenant schemas
    so that `token_blacklist` tables exist everywhere.
    """

    def setup_databases(self, **kwargs):
        # 1) Create the test database(s) as normal
        result = super().setup_databases(**kwargs)

        # 2) Migrate the shared (public) schema
        call_command(
            "migrate_schemas",
            "--shared",
            interactive=False,
            verbosity=1,
        )
        # 3) Migrate all tenant schemas
        call_command(
            "migrate_schemas",
            interactive=False,
            verbosity=1,
        )

        return result
