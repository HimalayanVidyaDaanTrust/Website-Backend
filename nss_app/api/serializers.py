from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Profile, Announcement, Download, Gallery, Brochure, Report, Contact, Event
from django.conf import settings

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name')
        read_only_fields = ('id',)

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'first_name', 'last_name')
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        return user

class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = Profile
        fields = ('id', 'user', 'bio', 'entry_number', 'mobile_number', 'webmail', 
                 'profile_pic', 'role', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at')

class AnnouncementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Announcement
        fields = ('id', 'title', 'content', 'date_posted', 'image', 'venue', 'time')
        read_only_fields = ('id', 'date_posted')

class DownloadSerializer(serializers.ModelSerializer):
    class Meta:
        model = Download
        fields = ('id', 'title', 'file', 'description', 'category', 'uploaded_date')
        read_only_fields = ('id', 'uploaded_date')

class GallerySerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()
    
    class Meta:
        model = Gallery
        fields = ('id', 'title', 'location', 'image', 'image_url', 'description', 'date', 'type', 'year')
        read_only_fields = ('id',)
    
    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request is not None:
                return request.build_absolute_uri(obj.image.url)
            return f"{settings.MEDIA_URL}{obj.image}"
        return None

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

class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = ('id', 'title', 'date', 'description', 'location', 'image', 
                 'is_featured', 'created_at', 'updated_at')
        read_only_fields = ('id', 'created_at', 'updated_at') 