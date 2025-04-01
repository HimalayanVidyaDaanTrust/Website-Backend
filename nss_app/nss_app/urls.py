"""
URL configuration for nss_app project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from api.views import (
    ContactViewSet, AnnouncementViewSet, DownloadViewSet, 
    GalleryViewSet, BrochureViewSet, ReportViewSet, EventViewSet,
    get_csrf_token
)

# Create a router for non-prefixed endpoints
non_prefixed_router = DefaultRouter()
non_prefixed_router.register(r'contact', ContactViewSet)
non_prefixed_router.register(r'announcements', AnnouncementViewSet)
non_prefixed_router.register(r'downloads', DownloadViewSet)
non_prefixed_router.register(r'gallery', GalleryViewSet)
non_prefixed_router.register(r'brochures', BrochureViewSet)
non_prefixed_router.register(r'reports', ReportViewSet)
non_prefixed_router.register(r'events', EventViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),  # All API endpoints with prefix
    path('', include(non_prefixed_router.urls)),  # Non-prefixed endpoints (like /contact/)
    path('csrf/', get_csrf_token, name='csrf'),  # Add non-prefixed CSRF endpoint
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
