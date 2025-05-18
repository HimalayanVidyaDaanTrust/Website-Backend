from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Profile, Announcement, Download, Gallery, Brochure, Report, Contact,PYP,STP,WTP, PYR,STR,WTR,ApprovalRequest, Camp,Update,Student
from django.conf import settings
from django.utils.html import format_html
from django.utils.safestring import mark_safe
import re

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name')
        read_only_fields = ('id',)

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    role = serializers.CharField(write_only=True)
    entry_number = serializers.CharField(write_only=True, required=False, allow_blank=True)
    mobile_number = serializers.CharField(write_only=True, required=False, allow_blank=True)
    webmail = serializers.EmailField(write_only=True, required=False, allow_blank=True)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'first_name', 'last_name', 
                 'role', 'entry_number', 'mobile_number', 'webmail')
    
    def create(self, validated_data):
        role = validated_data.pop('role', 'Slot Coordinator')
        entry_number = validated_data.pop('entry_number', None)
        mobile_number = validated_data.pop('mobile_number', None)
        webmail = validated_data.pop('webmail', None)
        
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        
        # Update profile
        profile = Profile.objects.get(user=user)
        profile.role = role
        profile.entry_number = entry_number
        profile.mobile_number = mobile_number
        profile.webmail = webmail
        profile.save()
        
        # Create approval request
        ApprovalRequest.objects.create(user=user, requested_role=role)
        
        return user

class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = Profile
        fields = ('id', 'user', 'bio', 'entry_number', 'mobile_number', 'webmail', 
                 'profile_pic', 'role', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

class ApprovalRequestSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = ApprovalRequest
        fields = ('id', 'user', 'username', 'email', 'full_name', 'status', 'requested_role', 
                 'message', 'created_at', 'updated_at', 'reviewed_by', 'review_comments')
        read_only_fields = ('id', 'user', 'username', 'email', 'created_at', 'updated_at')
    
    def get_full_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()
    
class AnnouncementSerializer(serializers.ModelSerializer):
    formatted_content = serializers.SerializerMethodField()
    
    class Meta:
        model = Announcement
        fields = ('id', 'title', 'content', 'formatted_content', 'date_posted', 'image', 'venue', 'time')
        read_only_fields = ('id', 'date_posted', 'formatted_content')
    
    def get_formatted_content(self, obj):
        try:
            if not obj.content:
                return ""
            
            text = obj.content.replace('\n', '<br>')
            
            # Pattern to identify URLs
            url_pattern = re.compile(r'(https?://[^\s<]+|www\.[^\s<]+)')
            
            # Replace URLs with HTML links
            def replace_url(match):
                url = match.group(0)
                if url.startswith('www.'):
                    url = 'http://' + url
                return f'<a href="{url}" target="_blank">{url}</a>'
            
            # Apply the replacement
            linked_text = url_pattern.sub(replace_url, text)
            return linked_text
        except Exception as e:
            # Fallback in case of any error
            return obj.content or ""

class DownloadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Download
        fields = ('id', 'title', 'file', 'description', 'category', 'uploaded_date')
        read_only_fields = ('id', 'uploaded_date')


class BrochureSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = Brochure
        fields = ('id', 'title', 'file', 'file_url', 'year', 'description', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_file_url(self, obj):
        if obj.file:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.file.url)
            return f"{settings.MEDIA_URL}{obj.file}"
        return None

class ReportSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = Report
        fields = ('id', 'title', 'file', 'file_url', 'year', 'location', 'description', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_file_url(self, obj):
        if obj.file:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.file.url)
            return f"{settings.MEDIA_URL}{obj.file}"
        return None

class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ('id', 'name', 'email', 'subject', 'message', 'created_at')
        read_only_fields = ('id', 'created_at')


class PYPSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = PYP
        fields = ('id', 'title', 'file', 'file_url', 'exam_date', 'location', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_file_url(self, obj):
        if obj.file:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.file.url)
            return f"{settings.MEDIA_URL}{obj.file}"
        return None

class STPSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = STP
        fields = ('id', 'title', 'file', 'file_url', 'exam_date', 'location', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_file_url(self, obj):
        if obj.file:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.file.url)
            return f"{settings.MEDIA_URL}{obj.file}"
        return None

class WTPSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = WTP
        fields = ('id', 'title', 'file', 'file_url', 'exam_date', 'location', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_file_url(self, obj):
        if obj.file:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.file.url)
            return f"{settings.MEDIA_URL}{obj.file}"
        return None



class PYRSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = PYR
        fields = ('id', 'title', 'file', 'file_url', 'result_date', 'location', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_file_url(self, obj):
        if obj.file:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.file.url)
            return f"{settings.MEDIA_URL}{obj.file}"
        return None

class STRSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = STR
        fields = ('id', 'title', 'file', 'file_url', 'result_date', 'location', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_file_url(self, obj):
        if obj.file:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.file.url)
            return f"{settings.MEDIA_URL}{obj.file}"
        return None

class WTRSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = WTR
        fields = ('id', 'title', 'file', 'file_url', 'result_date', 'location', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')
    
    def get_file_url(self, obj):
        if obj.file:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.file.url)
            return f"{settings.MEDIA_URL}{obj.file}"
        return None
    
class UpdateSerializer(serializers.ModelSerializer):
    author_name = serializers.SerializerMethodField()
    time_formatted = serializers.SerializerMethodField()
    
    class Meta:
        model = Update
        fields = ['id', 'camp', 'title', 'text', 'author', 'author_name', 
                  'created_at', 'updated_at', 'time', 'time_formatted', 'venue']
        read_only_fields = ['author_name', 'created_at', 'updated_at', 'time_formatted']

    def get_author_name(self, obj):
        return obj.author.get_full_name() or obj.author.username
        
    def get_time_formatted(self, obj):
        if obj.time:
            return obj.time.strftime('%I:%M %p, %d %b %Y')
        return obj.updated_at.strftime('%I:%M %p, %d %b %Y')

class CampSerializer(serializers.ModelSerializer):
    location = serializers.CharField(read_only=True)
    updates = UpdateSerializer(many=True, read_only=True)
    student_count = serializers.IntegerField(source='total_students', read_only=True)
    
    class Meta:
        model = Camp
        fields = ['id', 'title', 'year', 'city', 'state', 'location', 'image', 
                 'total_students', 'student_count', 'created_at', 'updated_at', 'updates']

class GallerySerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()
    camp_name = serializers.CharField(source='camp.name', read_only=True)
    location = serializers.CharField(read_only=True)
    year = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = Gallery
        fields = ('id', 'title', 'camp', 'camp_name', 'location', 'image', 'image_url', 
                 'description', 'date', 'type', 'year', 'student_count')
        read_only_fields = ('id', 'location', 'year', 'student_count')

    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.image.url)
            return f"{settings.MEDIA_URL}{obj.image}"
        return None

class StudentSerializer(serializers.ModelSerializer):
    avatar_url = serializers.SerializerMethodField()
    camp_name = serializers.CharField(source='camp.title', read_only=True)
    camp_location = serializers.CharField(source='camp.location', read_only=True)
    registration_date_formatted = serializers.SerializerMethodField()

    class Meta:
        model = Student
        fields = ('id', 'name', 'camp', 'camp_name', 'camp_location', 'standard',
                  'registration_date', 'registration_date_formatted', 'avatar',
                  'avatar_url', 'email', 'phone_number', 'address', 'school_name',
                  # Parental details
                  'father_name', 'father_occupation', 'father_phone_number',
                  'mother_name', 'mother_occupation', 'mother_phone_number',
                  # Principal details
                  'principal_name', 'principal_phone_number',
                  'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at', 'camp_name', 'camp_location')

    def get_avatar_url(self, obj):
        if obj.avatar:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.avatar.url)
            return f"{settings.MEDIA_URL}{obj.avatar}"
        return None

    def get_registration_date_formatted(self, obj):
        return obj.registration_date.strftime('%d-%m-%Y')