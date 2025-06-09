from django.db import models
from django_tenants.models import TenantMixin, DomainMixin

class Tenant(TenantMixin):
    name = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    auto_create_schema = True
    auto_drop_schema = True

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

class Domain(DomainMixin):
    class Meta:
        ordering = ['domain']

    def __str__(self):
        return self.domain