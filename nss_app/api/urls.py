from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import (
    UserRegisterView, UserProfileView, UserViewSet, api_index, login_view, logout_view,
    user_info, ContactViewSet, AnnouncementViewSet, DownloadViewSet, GalleryViewSet, 
    BrochureViewSet, ReportViewSet, EventViewSet, PYPViewSet, STPViewSet, WTPViewSet,
    PYRViewSet, STRViewSet, WTRViewSet, get_csrf_token,
    GalleryList, GalleryDetail, GalleryDownload,
    BrochureList, BrochureDetail, BrochureDownload,
    ReportList, ReportDetail, ReportDownload,
    PYPList, PYPDetail, PYPDownload,
    STPList, STPDetail, STPDownload,
    WTPList, WTPDetail, WTPDownload,
    PYRList, PYRDetail, PYRDownload,
    STRList, STRDetail, STRDownload,
    WTRList, WTRDetail, WTRDownload
)

router = DefaultRouter()
router.register(r'contact', ContactViewSet)
router.register(r'announcements', AnnouncementViewSet)
router.register(r'downloads', DownloadViewSet)
router.register(r'gallery', GalleryViewSet)
router.register(r'brochures', BrochureViewSet)
router.register(r'reports', ReportViewSet)
router.register(r'events', EventViewSet)
router.register(r'pyp', PYPViewSet)
router.register(r'stp', STPViewSet)

urlpatterns = [
    path('', api_index, name='api-index'),
    path('register/', UserRegisterView.as_view(), name='user-register'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('user-info/', user_info, name='user-info'),
    path('csrf/', get_csrf_token, name='csrf'),
    
    # Direct URL patterns for class-based views
    path('gallery-list/', GalleryList.as_view(), name='gallery-list'),
    path('gallery-detail/<int:pk>/', GalleryDetail.as_view(), name='gallery-detail'),
    path('gallery-download/<int:pk>/', GalleryDownload.as_view(), name='gallery-download'),
    
    # Add similar patterns for other class-based views
    # ...
] + router.urls