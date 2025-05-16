from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

# Register your models here.

# api/admin.py



class CustomUserAdmin(UserAdmin):
    """
    Custom admin interface for User model
    """
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_duo_authenticated')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'is_duo_authenticated')
    fieldsets = UserAdmin.fieldsets + (
        ('Duo Authentication', {'fields': ('is_duo_authenticated',)}),
    )

# Register the User model with the custom admin
admin.site.register(User, CustomUserAdmin)
