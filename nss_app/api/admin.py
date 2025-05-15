from django.contrib import admin
from .models import Profile, Announcement, Download, Gallery, Brochure, Report, Contact,PYP,PYR,STP,STR,WTP,WTR,Camp,Update,Student

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
class ReportsAdmin(admin.ModelAdmin):
    list_display = ('title', 'year', 'created_at')
    search_fields = ('title', 'description')
    list_filter = ('year', 'created_at')

@admin.register(PYP)
class PYPAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'exam_date', 'created_at')
    search_fields = ('title', 'location', 'description')
    list_filter = ('exam_date', 'created_at')

@admin.register(STP)
class STPAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'exam_date', 'created_at')
    search_fields = ('title', 'location', 'description')
    list_filter = ('exam_date', 'created_at')


@admin.register(WTP)
class WTPAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'exam_date', 'created_at')
    search_fields = ('title', 'location', 'description')
    list_filter = ('exam_date', 'created_at')


@admin.register(PYR)
class PYRAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'result_date', 'created_at')
    search_fields = ('title', 'location', 'description')
    list_filter = ('result_date', 'created_at')

@admin.register(STR)
class STRAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'result_date', 'created_at')
    search_fields = ('title', 'location', 'description')
    list_filter = ('result_date', 'created_at')

@admin.register(WTR)
class WTRAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'result_date', 'created_at')
    search_fields = ('title', 'location', 'description')
    list_filter = ('result_date', 'created_at')


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'subject', 'created_at')
    search_fields = ('name', 'email', 'subject', 'message')
    list_filter = ('created_at',)
    readonly_fields = ('created_at',)
    

@admin.register(Update)
class UpdateAdmin(admin.ModelAdmin):
    list_display = ('author', 'camp', 'created_at')
    search_fields = ('text', 'author__username', 'camp__name')
    list_filter = ('created_at', 'camp')
    
@admin.register(Camp)
class CampAdmin(admin.ModelAdmin):
    list_display = ('name', 'year', 'location', 'total_students', 'created_at')
    search_fields = ('name', 'location')
    list_filter = ('year', 'created_at')
    
@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    list_display = ('name', 'standard', 'camp', 'registration_date')
    list_filter = ('camp', 'standard')
    search_fields = ('name', 'email', 'phone_number')
    date_hierarchy = 'registration_date'
    fieldsets = [
        (None, {'fields': ['name', 'standard', 'camp']}),
        ('Contact Information', {'fields': ['email', 'phone_number', 'address']}),
        ('Profile', {'fields': ['avatar']})
    ]

# If Camp admin isn't already registered, add this:
class StudentInline(admin.TabularInline):
    model = Student
    extra = 0
