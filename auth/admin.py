from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from auth.models import TwoFactor

User = get_user_model()


for model in (User,):
    try:
        admin.site.unregister(model)
    except admin.sites.NotRegistered:
        pass


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display   = ('username', 'email', 'is_active', 'is_staff', 'two_factor_enabled')
    list_filter    = ('is_active', 'is_staff', 'is_superuser')
    search_fields  = ('username', 'email')
    ordering       = ('username',)

    def two_factor_enabled(self, obj):
        tf = getattr(obj, 'two_factor', None)
        return tf.enabled if tf else False
    two_factor_enabled.boolean = True
    two_factor_enabled.short_description = '2FA Enabled'


@admin.register(TwoFactor)
class TwoFactorAdmin(admin.ModelAdmin):
    list_display    = ('user', 'enabled', 'created')
    list_filter     = ('enabled',)
    search_fields   = ('user__username', 'user__email')
    readonly_fields = ('secret', 'created')


