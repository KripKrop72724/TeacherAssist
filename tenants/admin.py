from django.contrib import admin

from TeacherAssist.admin_mixins import PublicOnlyModelAdmin
from tenants.models import Tenant, Domain


@admin.register(Tenant)
class TenantAdmin(PublicOnlyModelAdmin):
    list_display   = ('name', 'schema_name', 'created_at')
    search_fields  = ('name', 'schema_name')
    ordering       = ('name',)
    readonly_fields= ('schema_name','created_at')

@admin.register(Domain)
class DomainAdmin(PublicOnlyModelAdmin):
    list_display   = ('domain', 'tenant', 'is_primary')
    list_filter    = ('is_primary',)
    search_fields  = ('domain',)
    ordering       = ('domain',)
