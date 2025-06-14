from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import (
    UserRegisterView, UserProfileView, api_index, logout_view,
    user_info, ContactViewSet, DownloadViewSet, GalleryViewSet,
    BrochureViewSet, ReportViewSet, get_csrf_token,
    GalleryList, GalleryDetail, GalleryDownload,
    CampViewSet, UpdateViewSet, StudentViewSet, update_register,
    TestPaperViewSet, TestResultViewSet, LoginView, ApprovalRequestViewSet
)

# ✅ CORRECT - Use router for ViewSets
router = DefaultRouter()
router.register(r'contact', ContactViewSet)
router.register(r'downloads', DownloadViewSet)
router.register(r'gallery', GalleryViewSet)
router.register(r'brochures', BrochureViewSet)
router.register(r'reports', ReportViewSet)
router.register(r'camp', CampViewSet)
router.register(r'updates', UpdateViewSet)
router.register(r'students', StudentViewSet)
router.register(r'test-papers', TestPaperViewSet)
router.register(r'test-results', TestResultViewSet)
router.register(r'approval-requests', ApprovalRequestViewSet)

urlpatterns = [
    path('', api_index, name='api-index'),
    path('register/', UserRegisterView.as_view(), name='user-register'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', logout_view, name='logout'),
    path('user-info/', user_info, name='user-info'),
    path('csrf/', get_csrf_token, name='csrf'),
    
    path('gallery-list/', GalleryList.as_view(), name='gallery-list'),
    path('gallery-detail/<int:pk>/', GalleryDetail.as_view(), name='gallery-detail'),
    path('gallery-download/<int:pk>/', GalleryDownload.as_view(), name='gallery-download'),
    
    path('camps/<int:camp_id>/students/', StudentViewSet.as_view({'get': 'list', 'post': 'create'}), name='camp-students'),
    path('camps/<int:camp_id>/updates/', UpdateViewSet.as_view({'get': 'list'}), name='camp-updates'),
    path('camps/<int:camp_id>/test-papers/', TestPaperViewSet.as_view({'get': 'list', 'post': 'create'}), name='camp-test-papers'),
    path('camps/<int:camp_id>/test-results/', TestResultViewSet.as_view({'get': 'list', 'post': 'create'}), name='camp-test-results'),
    
    path('add_update/', update_register, name='update-register'),
    path('test-papers/type/<str:type>/', TestPaperViewSet.as_view({'get': 'list'}), name='test-papers-by-type'),
    path('test-results/type/<str:type>/', TestResultViewSet.as_view({'get': 'list'}), name='test-results-by-type'),
    path('test-papers/filter/', TestPaperViewSet.as_view({'get': 'list'}), name='filter-test-papers'),
    path('test-results/filter/', TestResultViewSet.as_view({'get': 'list'}), name='filter-test-results'),
] + router.urls
