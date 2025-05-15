from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import (
    UserRegisterView, UserProfileView, api_index, login_view, logout_view,
    user_info, ContactViewSet, AnnouncementViewSet, DownloadViewSet, GalleryViewSet, 
    BrochureViewSet, ReportViewSet, PYPViewSet, STPViewSet, WTPViewSet,
    PYRViewSet, STRViewSet, WTRViewSet, get_csrf_token,
    GalleryList, GalleryDetail, GalleryDownload,
    PYPList, PYPDetail, PYPDownload,
    STPList, STPDetail, STPDownload,
    WTPList, WTPDetail, WTPDownload,
    PYRList, PYRDetail, PYRDownload,
    STRList, STRDetail, STRDownload,
    WTRList, WTRDetail, WTRDownload,
    CampViewSet,UpdateViewSet
)

router = DefaultRouter()
router.register(r'contact', ContactViewSet)
router.register(r'announcements', AnnouncementViewSet)
router.register(r'downloads', DownloadViewSet)
router.register(r'gallery', GalleryViewSet)
router.register(r'brochures', BrochureViewSet)
router.register(r'reports', ReportViewSet)
router.register(r'pyp', PYPViewSet)
router.register(r'stp', STPViewSet)
router.register(r'wtp', WTPViewSet)
router.register(r'pyr', PYRViewSet)
router.register(r'str', STRViewSet)
router.register(r'wtr', WTRViewSet)
router.register(r'camps', CampViewSet)
router.register(r'updates', UpdateViewSet)


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
    
    path('pyp-list/', PYPList.as_view(), name='pyp-list'),
    path('pyp-detail/<int:pk>/', PYPDetail.as_view(), name='pyp-detail'),
    path('pyp-download/<int:pk>/', PYPDownload.as_view(), name='pyp-download'),
    
    path('stp-list/', STPList.as_view(), name='stp-list'),
    path('stp-detail/<int:pk>/', STPDetail.as_view(), name='stp-detail'),
    path('stp-download/<int:pk>/', STPDownload.as_view(), name='stp-download'),
    
    path('wtp-list/', WTPList.as_view(), name='wtp-list'),
    path('wtp-detail/<int:pk>/', WTPDetail.as_view(), name='wtp-detail'),
    path('wtp-download/<int:pk>/', WTPDownload.as_view(), name='wtp-download'),
    
    path('pyr-list/', PYRList.as_view(), name='pyr-list'),
    path('pyr-detail/<int:pk>/', PYRDetail.as_view(), name='pyr-detail'),
    path('pyr-download/<int:pk>/', PYRDownload.as_view(), name='pyr-download'),

    path('str-list/', STRList.as_view(), name='str-list'),
    path('str-detail/<int:pk>/', STRDetail.as_view(), name='str-detail'),
    path('str-download/<int:pk>/', STRDownload.as_view(), name='str-download'),

    path('wtr-list/', WTRList.as_view(), name='wtr-list'),
    path('wtr-detail/<int:pk>/', WTRDetail.as_view(), name='wtr-detail'),
    path('wtr-download/<int:pk>/', WTRDownload.as_view(), name='wtr-download'),
    
    
    
    # Add similar patterns for other class-based views
    # ...
] + router.urls