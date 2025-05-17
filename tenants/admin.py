from django.contrib import admin

from tenants.models import Tenant, Domain


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display   = ('name', 'schema_name', 'created_at')
    search_fields  = ('name', 'schema_name')
    ordering       = ('name',)
    readonly_fields= ('schema_name','created_at')

@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display   = ('domain', 'tenant', 'is_primary')
    list_filter    = ('is_primary',)
    search_fields  = ('domain',)
    ordering       = ('domain',)
