from django.contrib import admin
from django_tenants.utils import get_public_schema_name

class PublicOnlyModelAdmin(admin.ModelAdmin):

    def has_module_permission(self, request):
        return request.tenant.schema_name == get_public_schema_name()

    def has_view_permission(self, request, obj=None):
        return request.tenant.schema_name == get_public_schema_name()

    def has_add_permission(self, request):
        return request.tenant.schema_name == get_public_schema_name()

    def has_change_permission(self, request, obj=None):
        return request.tenant.schema_name == get_public_schema_name()

    def has_delete_permission(self, request, obj=None):
        return request.tenant.schema_name == get_public_schema_name()
