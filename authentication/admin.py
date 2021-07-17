from django.contrib import admin
from .models import User


class UserAdmin(admin.ModelAdmin):
    list_display = ('id','username', 'email', 'auth_provider', 'is_verified', 'is_active')




# Register your models here.
admin.site.register(User, UserAdmin)
