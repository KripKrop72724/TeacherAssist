from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken, BlacklistedToken
)

from auth.models import TwoFactor

User = get_user_model()

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display   = ('username', 'email', 'is_active', 'is_staff', 'get_2fa')
    list_filter    = ('is_active', 'is_staff', 'is_superuser')
    search_fields  = ('username','email')
    ordering       = ('username',)

    def get_2fa(self, obj):
        tf = getattr(obj, 'two_factor', None)
        return tf.enabled if tf else False
    get_2fa.boolean = True
    get_2fa.short_description = '2FA Enabled'

@admin.register(TwoFactor)
class TwoFactorAdmin(admin.ModelAdmin):
    list_display   = ('user', 'enabled', 'created')
    list_filter    = ('enabled',)
    search_fields  = ('user__username','user__email')
    readonly_fields= ('secret','created')

@admin.register(OutstandingToken)
class OutstandingTokenAdmin(admin.ModelAdmin):
    list_display  = ('user', 'jti', 'created_at')
    search_fields = ('user__username',)

@admin.register(BlacklistedToken)
class BlacklistedTokenAdmin(admin.ModelAdmin):
    list_display = ('token',)
