from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken import views as auth_views
from . import views

router = DefaultRouter()
router.register(r'announcements', views.AnnouncementViewSet)
router.register(r'downloads', views.DownloadViewSet)
router.register(r'gallery', views.GalleryViewSet)
router.register(r'brochures', views.BrochureViewSet)
router.register(r'reports', views.ReportViewSet)
router.register(r'contact', views.ContactViewSet)
router.register(r'events', views.EventViewSet)
router.register(r'pyp', views.PYPViewSet)
router.register(r'stp', views.STPViewSet)
router.register(r'wtp', views.WTPViewSet)
router.register(r'pyr', views.PYRViewSet)
router.register(r'str', views.STRViewSet)
router.register(r'wtr', views.WTRViewSet)


urlpatterns = [
    path('', include(router.urls)),
    path('register/', views.UserRegisterView.as_view(), name='user-register'),
    path('profile/', views.UserProfileView.as_view(), name='user-profile'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('csrf/', views.get_csrf_token, name='csrf'),
    path('api-token-auth/', auth_views.obtain_auth_token, name='api-token-auth'),
] 