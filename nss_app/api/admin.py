from django.contrib import admin
from .models import Profile, Download, Gallery, Brochure, Report, Contact,Camp,Update,Student,TestPaper,TestResult

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'entry_number', 'mobile_number', 'role', 'created_at')
    search_fields = ('user__username', 'entry_number', 'mobile_number')
    list_filter = ('role', 'created_at')

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

# @admin.register(PYP)
# class PYPAdmin(admin.ModelAdmin):
#     list_display = ('title', 'location', 'exam_date', 'created_at')
#     search_fields = ('title', 'location', 'description')
#     list_filter = ('exam_date', 'created_at')

# @admin.register(STP)
# class STPAdmin(admin.ModelAdmin):
#     list_display = ('title', 'location', 'exam_date', 'created_at')
#     search_fields = ('title', 'location', 'description')
#     list_filter = ('exam_date', 'created_at')


# @admin.register(WTP)
# class WTPAdmin(admin.ModelAdmin):
#     list_display = ('title', 'location', 'exam_date', 'created_at')
#     search_fields = ('title', 'location', 'description')
#     list_filter = ('exam_date', 'created_at')


# @admin.register(PYR)
# class PYRAdmin(admin.ModelAdmin):
#     list_display = ('title', 'location', 'result_date', 'created_at')
#     search_fields = ('title', 'location', 'description')
#     list_filter = ('result_date', 'created_at')

# @admin.register(STR)
# class STRAdmin(admin.ModelAdmin):
#     list_display = ('title', 'location', 'result_date', 'created_at')
#     search_fields = ('title', 'location', 'description')
#     list_filter = ('result_date', 'created_at')

# @admin.register(WTR)
# class WTRAdmin(admin.ModelAdmin):
#     list_display = ('title', 'location', 'result_date', 'created_at')
#     search_fields = ('title', 'location', 'description')
#     list_filter = ('result_date', 'created_at')


@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'subject', 'created_at')
    search_fields = ('name', 'email', 'subject', 'message')
    list_filter = ('created_at',)
    readonly_fields = ('created_at',)
    

@admin.register(Update)
class UpdateAdmin(admin.ModelAdmin):
    # Update list_display to include title, venue, and time fields
    list_display = ('title', 'author', 'camp', 'venue', 'time', 'created_at')
    
    # Update search_fields to include title and venue
    search_fields = ('title', 'text', 'venue', 'author__username', 'camp__name')
    
    # Update list_filter to include time field
    list_filter = ('created_at', 'updated_at', 'time', 'camp')
    
    # Add date hierarchy for better date navigation
    date_hierarchy = 'created_at'
    
    # Add fieldsets for better organization in the edit form
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'text', 'camp', 'author')
        }),
        ('Event Details', {
            'fields': ('venue', 'time')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    # Make created_at and updated_at read-only
    readonly_fields = ('created_at', 'updated_at')

    
@admin.register(Camp)
class CampAdmin(admin.ModelAdmin):
    list_display = ('title', 'year', 'location', 'total_students', 'created_at')
    search_fields = ('title', 'location')
    list_filter = ('year', 'created_at')
    
@admin.register(Student)
class StudentAdmin(admin.ModelAdmin):
    list_display = ('name', 'standard', 'camp', 'school_name', 'registration_date')
    list_filter = ('camp', 'standard', 'registration_date')
    search_fields = ('name', 'email', 'phone_number', 'father_name', 'mother_name', 'principal_name', 'school_name')
    date_hierarchy = 'registration_date'
    
    fieldsets = [
        (None, {'fields': ['name', 'standard', 'camp', 'school_name']}),
        ('Contact Information', {'fields': ['email', 'phone_number', 'address']}),
        ('Parent Information', {'fields': [
            'father_name', 'father_occupation', 'father_phone_number',
            'mother_name', 'mother_occupation', 'mother_phone_number'
        ]}),
        ('Principal Information', {'fields': ['principal_name', 'principal_phone_number']}),
        ('Profile', {'fields': ['avatar']}),
    ]
    
# If Camp admin isn't already registered, add this:
class StudentInline(admin.TabularInline):
    model = Student
    extra = 0


# admin.py
@admin.register(TestPaper)
class TestPaperAdmin(admin.ModelAdmin):
    list_display = ('title', 'type', 'exam_date', 'camp', 'created_at')
    search_fields = ('title', 'description')
    list_filter = ('type', 'exam_date', 'camp', 'created_at')
    date_hierarchy = 'exam_date'

@admin.register(TestResult)
class TestResultAdmin(admin.ModelAdmin):
    list_display = ('title', 'type', 'result_date', 'camp', 'created_at')
    search_fields = ('title', 'description')
    list_filter = ('type', 'result_date', 'camp', 'created_at')
    date_hierarchy = 'result_date'
