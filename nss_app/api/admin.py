from django.contrib import admin
from .models import Profile, Announcement, Download, Gallery, Brochure, Report, Contact, Event

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'entry_number', 'mobile_number', 'role', 'created_at')
    search_fields = ('user__username', 'entry_number', 'mobile_number')
    list_filter = ('role', 'created_at')

@admin.register(Announcement)
class AnnouncementAdmin(admin.ModelAdmin):
    list_display = ('title', 'date_posted')
    search_fields = ('title', 'content')
    list_filter = ('date_posted',)

@admin.register(Download)
class DownloadAdmin(admin.ModelAdmin):
    list_display = ('title', 'category', 'uploaded_date')
    search_fields = ('title', 'description')
    list_filter = ('category', 'uploaded_date')

@admin.register(Gallery)
class GalleryAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'type', 'date', 'year')
    search_fields = ('title', 'location', 'description')
    list_filter = ('type', 'year', 'date')

@admin.register(Brochure)
class BrochureAdmin(admin.ModelAdmin):
    list_display = ('title', 'year', 'created_at')
    search_fields = ('title', 'description')
    list_filter = ('year', 'created_at')

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'year', 'created_at')
    search_fields = ('title', 'location', 'description')
    list_filter = ('year', 'created_at')

@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'subject', 'created_at')
    search_fields = ('name', 'email', 'subject', 'message')
    list_filter = ('created_at',)
    readonly_fields = ('created_at',)

@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ('title', 'date', 'location', 'is_featured', 'created_at')
    search_fields = ('title', 'description', 'location')
    list_filter = ('is_featured', 'date', 'created_at')
    list_editable = ('is_featured',) 