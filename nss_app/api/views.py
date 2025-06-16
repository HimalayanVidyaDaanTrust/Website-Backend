from rest_framework import viewsets, permissions, status, generics, renderers
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,BasePermission, SAFE_METHODS
from rest_framework.authentication import SessionAuthentication, BasicAuthentication,TokenAuthentication
from django.contrib.auth.models import User
from django.db import IntegrityError
import traceback
import logging
from .models import Profile, Download, Gallery, Brochure, Report, Contact,ApprovalRequest,Camp,Update,Student,TestPaper,TestResult
from .serializers import (
    UserSerializer, UserRegisterSerializer, ProfileSerializer,ApprovalRequestSerializer,
    DownloadSerializer, GallerySerializer,
    BrochureSerializer, ReportSerializer, ContactSerializer,CampSerializer,UpdateSerializer,StudentSerializer,TestPaperSerializer,TestResultSerializer
)
from django.http import FileResponse, Http404, JsonResponse
from django.views import View
from urllib.parse import quote as urlquote
import os
from django.conf import settings
from rest_framework.decorators import action
from rest_framework.negotiation import BaseContentNegotiation
from rest_framework.pagination import PageNumberPagination
from django.db.models import Q
from django.core.mail import send_mail
from django.template.loader import render_to_string
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.models import Token
from django.middleware.csrf import get_token
import mimetypes
from rest_framework.decorators import api_view, permission_classes


logger = logging.getLogger(__name__)
class CsrfExemptSessionAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return  # Skip CSRF check
    
class IgnoreClientContentNegotiation(BaseContentNegotiation):
    def select_parser(self, request, parsers):
        return parsers[0]

    def select_renderer(self, request, renderers, format_suffix=None):
        return (renderers[0], renderers[0].media_type)


class IsCoordinator(permissions.BasePermission):
    def has_permission(self, request, view):
        try:
            if not request.user.is_authenticated:
                return False
                
            if not hasattr(request.user, 'profile'):
                return False
                
            return request.user.profile.role == 'Coordinator'
        except Exception as e:
            return False
class IsCoordinatorOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        # Allow safe methods (GET, HEAD, OPTIONS)
        if request.method in SAFE_METHODS:
            return True
        
        # Only allow write if user is authenticated and a Coordinator
        return (
            request.user.is_authenticated and
            hasattr(request.user, 'profile') and
            request.user.profile.role == 'Coordinator'
        )
        
def user_has_camp_access(user, camp_id):
    """Check if user has access to specific camp"""
    if not user.is_authenticated or not hasattr(user, 'profile'):
        return False
    
    profile = user.profile
    
    # Coordinators have access to all camps
    if profile.role == 'Coordinator':
        return True
    
    # Slot coordinators only have access to allocated camps
    if profile.role == 'Slot Coordinator':
        return profile.allocated_camps.filter(id=camp_id).exists()
    
    return False

def get_user_accessible_camps(user):
    """Get camps that user has access to"""
    if not user.is_authenticated or not hasattr(user, 'profile'):
        return Camp.objects.all()
    
    profile = user.profile
    
    # Coordinators have access to all camps
    if profile.role == 'Coordinator':
        return Camp.objects.all()
    
    # Slot coordinators only have access to allocated camps
    if profile.role == 'Slot Coordinator':
        return profile.allocated_camps.all()
    
    return Camp.objects.none()

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_info(request):
    user = request.user
    data = {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
    }
    return Response(data)

@ensure_csrf_cookie
def get_csrf_token(request):
    """
    Endpoint to ensure a CSRF cookie is set and return the token
    """
    token = get_token(request)  # Add this line to get the actual token
    
    response = JsonResponse({
        "success": "CSRF cookie set",
        "csrfToken": token  # Add this line to return the token
    })
    
    # Get the origin from the request
    origin = request.headers.get('Origin', '')
    allowed_origins = [
        'http://localhost:5174',
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://127.0.0.1:5174',
        'https://himalayanvidyadaan.org',
        'https://www.himalayanvidyadaan.org',
        'https://api.himalayanvidyadaan.org',
        'https://admin.himalayanvidyadaan.org'
    ]

    if origin in allowed_origins:
        response["Access-Control-Allow-Origin"] = origin
        response["Access-Control-Allow-Credentials"] = "true"
        response["Access-Control-Allow-Headers"] = "Origin, X-Requested-With, Content-Type, Accept, Authorization, X-CSRFToken"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"

    return response

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({'error': 'Username and password required'}, status=400)

        try:
            user_obj = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=401)

        # Check if user was rejected
        try:
            approval_request = ApprovalRequest.objects.get(user=user_obj)
            if approval_request.status == 'rejected':
                return Response({
                    'error': 'Your previous registration request was rejected. Please register again with a new account.',
                    'rejection_reason': approval_request.review_comments or 'No specific reason provided.',
                    'should_register_again': True
                }, status=401)
        except ApprovalRequest.DoesNotExist:
            pass

        # Check password manually
        if not user_obj.check_password(password):
            return Response({'error': 'Invalid credentials'}, status=401)
        
        # Check if user is inactive
        if not user_obj.is_active:
            return Response({'error': 'Your account is pending approval. Please wait for administrator approval.'}, status=401)

        # Check if account is approved
        try:
            approval_request = ApprovalRequest.objects.get(user=user_obj)
            if approval_request.status != 'approved':
                return Response({'error': 'Your account is pending approval. Please wait for administrator approval.'}, status=401)
        except ApprovalRequest.DoesNotExist:
            return Response({'error': 'No approval request found. Please contact administrator.'}, status=401)

        # Login success - create token
        token, _ = Token.objects.get_or_create(user=user_obj)

        # Get profile data
        try:
            profile = Profile.objects.get(user=user_obj)
            profile_data = {
                'role': profile.role,
                'entry_number': profile.entry_number,
                'mobile_number': profile.mobile_number,
                'email': profile.email
            }
        except Profile.DoesNotExist:
            profile_data = {}

        # Approval info
        approval_status = approval_request.status
        can_access_admin = approval_status == 'approved'
        review_comments = approval_request.review_comments

        # Superuser or coordinator can access admin
        if user_obj.is_superuser or (hasattr(user_obj, 'profile') and user_obj.profile.role == 'Coordinator'):
            can_access_admin = True

        # Prepare response
        response = Response({
            'token': token.key,
            'user_id': user_obj.pk,
            'username': user_obj.username,
            'first_name': user_obj.first_name,
            'last_name': user_obj.last_name,
            'email': user_obj.email,
            'profile': profile_data,
            'approval_status': approval_status,
            'can_access_admin': can_access_admin,
            'review_comments': review_comments
        })

        # Add CORS headers
        origin = request.headers.get('Origin', '')
        allowed_origins = [
            'http://localhost:5174',
            'http://localhost:5173',
            'http://127.0.0.1:5173',
            'http://127.0.0.1:5174',
            'https://himalayanvidyadaan.org',
            'https://www.himalayanvidyadaan.org',
            'https://api.himalayanvidyadaan.org',
            'https://admin.himalayanvidyadaan.org'
        ]

        if origin in allowed_origins:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Allow-Headers"] = "Origin, X-Requested-With, Content-Type, Accept, Authorization, X-CSRFToken"
            response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"

        return response

class ApprovalRequestViewSet(viewsets.ModelViewSet):
    """
    ViewSet for approval requests.
    - Coordinators can view all and approve/reject
    - Slot Coordinators can only view their own
    """
    queryset = ApprovalRequest.objects.all().order_by('-created_at')
    serializer_class = ApprovalRequestSerializer
    authentication_classes = [TokenAuthentication]
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'approve', 'reject']:
            permission_classes = [IsCoordinator]
        else:
            permission_classes = [permissions.IsAuthenticated]
        return [permission() for permission in permission_classes]
    
    def get_queryset(self):
        """
        - Coordinators: all approval requests
        - Others: only their own
        """
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.role == 'Coordinator':
            return ApprovalRequest.objects.all().order_by('-created_at')
        return ApprovalRequest.objects.filter(user=user).order_by('-created_at')
    
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        approval_request = self.get_object()
        if approval_request.status != 'pending':
            return Response({"error": "This request has already been processed"}, status=status.HTTP_400_BAD_REQUEST)

        # Get the camp allocation data from request
        allocated_camp_ids = request.data.get('allocated_camps', [])
        
        # Approve the request
        approval_request.status = 'approved'
        approval_request.reviewed_by = request.user
        approval_request.review_comments = request.data.get('comments', '')
        approval_request.save()

        # Activate the user and update profile
        user = approval_request.user
        user.is_active = True
        user.save()

        # Update user's profile role and allocate camps
        profile = Profile.objects.get(user=user)
        profile.role = approval_request.requested_role
        
        # If user is slot coordinator, allocate specific camps
        if approval_request.requested_role == 'Slot Coordinator' and allocated_camp_ids:
            # Clear existing allocations and add new ones
            profile.allocated_camps.clear()
            for camp_id in allocated_camp_ids:
                try:
                    camp = Camp.objects.get(id=camp_id)
                    profile.allocated_camps.add(camp)
                except Camp.DoesNotExist:
                    continue
        elif approval_request.requested_role == 'Coordinator':
            # Coordinators have access to all camps, so no specific allocation needed
            profile.allocated_camps.clear()
        
        profile.save()

        return Response({
            "message": f"User {user.username} has been approved as {approval_request.requested_role}",
            "approval_request": ApprovalRequestSerializer(approval_request).data,
            "allocated_camps": [camp.id for camp in profile.allocated_camps.all()]
        })

    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        approval_request = self.get_object()
        if approval_request.status != 'pending':
            return Response({"error": "This request has already been processed"}, 
                        status=status.HTTP_400_BAD_REQUEST)
        
        approval_request.status = 'rejected'
        approval_request.reviewed_by = request.user
        approval_request.review_comments = request.data.get('comments', '')
        approval_request.save()
        
        
        return Response({
            "message": f"Request from {approval_request.user.username} has been rejected",
            "approval_request": ApprovalRequestSerializer(approval_request).data
        })
        
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def check_approval_status(request):
    """
    Check the approval status for the logged-in user
    """
    try:
        approval_request = ApprovalRequest.objects.get(user=request.user)
        return Response({
            "status": approval_request.status,
            "requested_role": approval_request.requested_role,
            "review_comments": approval_request.review_comments,
            "can_access_admin": approval_request.status == 'approved'
        })
    except ApprovalRequest.DoesNotExist:
        return Response({
            "status": "not_requested",
            "can_access_admin": False
        })
        
        
class UserRegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        try:
            logger.info(f"Received registration data: {request.data}")
            
            # Check if user already exists by username or email
            username = request.data.get('username', '')
            email = request.data.get('email', '')
            
            if User.objects.filter(username=username).exists():
                logger.warning(f"Username {username} already exists")
                return Response({
                    'error': 'Username already exists'
                }, status=status.HTTP_400_BAD_REQUEST)
                
            if User.objects.filter(email=email).exists():
                logger.warning(f"Email {email} already exists")
                return Response({
                    'error': 'Email already exists'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = self.get_serializer(data=request.data)
            
            if not serializer.is_valid():
                logger.error(f"Validation errors: {serializer.errors}")
                return Response({
                    'error': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
            
            logger.info(f"Serializer validated data: {serializer.validated_data}")
            
            # Create user and profile
            try:
                user = self.perform_create(serializer)
                logger.info(f"User created successfully: {user.username}")
                
                headers = self.get_success_headers(serializer.data)
                return Response({
                    'message': 'Registration successful',
                    'user': serializer.data
                }, status=status.HTTP_201_CREATED, headers=headers)
            except Exception as create_error:
                # If user was created but profile creation failed, cleanup by deleting user
                try:
                    if 'username' in serializer.validated_data and User.objects.filter(username=serializer.validated_data['username']).exists():
                        User.objects.filter(username=serializer.validated_data['username']).delete()
                        logger.info(f"Cleaned up user {serializer.validated_data['username']} after profile creation failed")
                except Exception as cleanup_error:
                    logger.error(f"Error during cleanup: {str(cleanup_error)}")
                
                raise create_error
                
        except IntegrityError as e:
            logger.error(f"Integrity error: {str(e)}")
            if 'unique constraint' in str(e).lower():
                if 'username' in str(e).lower():
                    return Response({
                        'error': 'Username already exists'
                    }, status=status.HTTP_400_BAD_REQUEST)
                elif 'email' in str(e).lower():
                    return Response({
                        'error': 'Email already exists'
                    }, status=status.HTTP_400_BAD_REQUEST)
                elif 'user_id' in str(e).lower():
                    return Response({
                        'error': 'User profile already exists'
                    }, status=status.HTTP_400_BAD_REQUEST)
            return Response({
                'error': f'Registration failed due to database integrity error: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response({
                'error': f'Registration failed: {str(e)}'
            }, status=status.HTTP_400_BAD_REQUEST)
            
    def perform_create(self, serializer):
        return serializer.save()

class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [TokenAuthentication] 
    
    def get_object(self):
        # Create profile if it doesn't exist
        profile, created = Profile.objects.get_or_create(user=self.request.user)
        return profile
    def patch(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'per_page'
    max_page_size = 100

class DownloadViewSet(viewsets.ModelViewSet):
    queryset = Download.objects.all().order_by('-uploaded_date')
    serializer_class = DownloadSerializer
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            permission_classes = [permissions.AllowAny]
        else:
            permission_classes = [permissions.IsAdminUser]
        return [permission() for permission in permission_classes]

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        download_obj = self.get_object()
        file_path = download_obj.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)

class GalleryViewSet(viewsets.ModelViewSet):
    queryset = Gallery.objects.all().order_by('-date')
    serializer_class = GallerySerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_queryset(self):
        queryset = Gallery.objects.all().order_by('-date')
        
        # Filter by camp ID
        camp_id = self.request.query_params.get('camp_id')
        if camp_id:
            queryset = queryset.filter(camp_id=camp_id)
            
        # Filter by location (for backward compatibility)
        location = self.request.query_params.get('location')
        if location:
            queryset = queryset.filter(location__icontains=location)
            
        # Filter by city and state from camp
        city = self.request.query_params.get('city')
        if city:
            queryset = queryset.filter(camp__city__iexact=city)
            
        state = self.request.query_params.get('state')
        if state:
            queryset = queryset.filter(camp__state__iexact=state)
            
        # Filter by type
        type_param = self.request.query_params.get('type')
        if type_param:
            queryset = queryset.filter(type=type_param)
            
        # Filter by year
        year = self.request.query_params.get('year')
        if year:
            queryset = queryset.filter(year=year)
            
        return queryset
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    @action(detail=False, methods=['get'])
    def by_type(self, request):
        type_param = request.query_params.get('type')
        if type_param:
            queryset = self.get_queryset().filter(type=type_param)
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        return Response({'error': 'Type parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        gallery_obj = self.get_object()
        file_path = gallery_obj.image.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
        
    @action(detail=False, methods=['get'])
    def camps(self, request):
        """Get list of all camps that have gallery items"""
        camps = Camp.objects.filter(gallery_images__isnull=False).distinct()
        from .serializers import CampSerializer
        serializer = CampSerializer(camps, many=True, context={'request': request})
        return Response(serializer.data)

class FileDownloadView(View):
    def get(self, request, file_path):
        try:
            # Get the file from the media directory
            file_path = os.path.join(settings.MEDIA_ROOT, file_path)
            if not os.path.exists(file_path):
                raise Http404("File not found")
            
            # Get the filename from the path
            filename = os.path.basename(file_path)
            
            # Open the file and create response
            response = FileResponse(open(file_path, 'rb'))
            response['Content-Disposition'] = f'attachment; filename="{urlquote(filename)}"'
            return response
        except Exception as e:
            raise Http404(str(e))

class BrochureViewSet(viewsets.ModelViewSet):
    queryset = Brochure.objects.all().order_by('-year', '-created_at')
    serializer_class = BrochureSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    authentication_classes=[TokenAuthentication]
    content_negotiation_class = IgnoreClientContentNegotiation
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        brochure_obj = self.get_object()
        file_path = brochure_obj.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)

class ReportViewSet(viewsets.ModelViewSet):
    queryset = Report.objects.all().order_by('-year', '-created_at')
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    authentication_classes=[TokenAuthentication]
    content_negotiation_class = IgnoreClientContentNegotiation
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        report_obj = self.get_object()
        file_path = report_obj.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
    
@method_decorator(csrf_exempt, name='dispatch')
class ContactViewSet(viewsets.ModelViewSet):
    queryset = Contact.objects.all()
    serializer_class = ContactSerializer
    permission_classes = [permissions.AllowAny]
    authentication_classes = [CsrfExemptSessionAuthentication, BasicAuthentication]
    http_method_names = ['get', 'post', 'head', 'options']

    def create(self, request, *args, **kwargs):
        logger.info(f"Contact form data: {request.data}")
        logger.info(f"Request headers: {request.headers}")
        logger.info(f"Contact form endpoint accessed")

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            contact = serializer.save()
            self.send_email(contact)
            response_data = {
                'message': 'Message sent successfully',
                'contact': serializer.data
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        logger.error(f"Validation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def send_email(self, contact):
        try:
            # Construct HTML message
            msg = MIMEMultipart()
            msg['From'] = settings.EMAIL_HOST_USER
            msg['To'] = 'tejashvikumawat@gmail.com'
            msg['Subject'] = f"New Contact Form Submission: {contact.subject}"

            html_body = f"""
            <html>
            <body>
                <h2>New Contact Form Submission</h2>
                <p><strong>Name:</strong> {contact.name}</p>
                <p><strong>Email:</strong> {contact.email}</p>
                <p><strong>Subject:</strong> {contact.subject}</p>
                <p><strong>Message:</strong></p>
                <p>{contact.message}</p>
            </body>
            </html>
            """

            msg.attach(MIMEText(html_body, 'html'))

            logger.info("Connecting to SMTP server...")
            server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
            server.set_debuglevel(0)
            server.starttls()
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            server.send_message(msg)
            server.quit()

            logger.info("Email sent successfully.")
            return True

        except Exception as e:
            logger.error(f"Primary email send failed: {e}")
            logger.error(traceback.format_exc())

            # Fallback using Django's send_mail
            try:
                logger.info("Trying fallback with send_mail...")
                subject = f"New Contact Form Submission: {contact.subject}"
                plain_message = (
                    f"Name: {contact.name}\n"
                    f"Email: {contact.email}\n"
                    f"Subject: {contact.subject}\n"
                    f"Message: {contact.message}"
                )
                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=['tejashvikumawat@gmail.com'],
                    fail_silently=False,
                )
                logger.info("Fallback email sent successfully.")
                return True
            except Exception as fallback_error:
                logger.error(f"Fallback email failed: {fallback_error}")
                logger.error(traceback.format_exc())
                return False

class GalleryList(generics.ListCreateAPIView):
    queryset = Gallery.objects.all().order_by('-date')
    serializer_class = GallerySerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_queryset(self):
        queryset = Gallery.objects.all().order_by('-date')
        location = self.request.query_params.get('location')
        if location:
            queryset = queryset.filter(location=location)
        return queryset

class GalleryDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Gallery.objects.all()
    serializer_class = GallerySerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class GalleryDownload(generics.RetrieveAPIView):
    queryset = Gallery.objects.all()
    serializer_class = GallerySerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    
    def retrieve(self, request, *args, **kwargs):
        gallery = self.get_object()
        if not gallery.image:
            raise Http404("Image not found")
        
        try:
            response = FileResponse(gallery.image.open('rb'))
            response['Content-Disposition'] = f'attachment; filename="{gallery.image.name.split("/")[-1]}"'
            return response
        except Exception as e:
            raise Http404(f"Error serving file: {str(e)}")

class BrochureList(generics.ListCreateAPIView):
    queryset = Brochure.objects.all()
    serializer_class = BrochureSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class BrochureDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Brochure.objects.all()
    serializer_class = BrochureSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class BrochureDownload(generics.RetrieveAPIView):
    queryset = Brochure.objects.all()
    serializer_class = BrochureSerializer
    permission_classes = [permissions.AllowAny]
    
    def retrieve(self, request, *args, **kwargs):
        brochure = self.get_object()
        if not brochure.file:
            raise Http404("File not found")
        
        try:
            response = FileResponse(brochure.file.open('rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{brochure.file.name.split("/")[-1]}"'
            return response
        except Exception as e:
            raise Http404(f"Error serving file: {str(e)}")

class ReportList(generics.ListCreateAPIView):
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class ReportDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class ReportDownload(generics.RetrieveAPIView):
    queryset = Report.objects.all()
    serializer_class = ReportSerializer
    permission_classes = [permissions.AllowAny]
    
    def retrieve(self, request, *args, **kwargs):
        report = self.get_object()
        if not report.file:
            raise Http404("File not found")
        
        try:
            response = FileResponse(report.file.open('rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{report.file.name.split("/")[-1]}"'
            return response
        except Exception as e:
            raise Http404(f"Error serving file: {str(e)}")
        
@method_decorator(csrf_exempt, name='dispatch')
class CampViewSet(viewsets.ModelViewSet):
    queryset = Camp.objects.all().order_by('-year', 'state', 'city')
    serializer_class = CampSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    authentication_classes = [TokenAuthentication]

    def get_queryset(self):
        """
        Apply role-based filtering for camps
        - Coordinators: access all camps
        - Slot Coordinators: access only allocated camps
        """
        queryset = get_user_accessible_camps(self.request.user)
        state = self.request.query_params.get('state')
        if state:
            queryset = queryset.filter(state__iexact=state)
        city = self.request.query_params.get('city')
        if city:
            queryset = queryset.filter(city__iexact=city)
        year = self.request.query_params.get('year')
        if year:
            queryset = queryset.filter(year=year)
        return queryset

    def retrieve(self, request, *args, **kwargs):
        """Check if user has access to specific camp"""
        camp_id = kwargs.get('pk')
        
        if not user_has_camp_access(request.user, camp_id):
            return Response(
                {"error": "You don't have access to this camp"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        return super().retrieve(request, *args, **kwargs)

    @action(detail=True, methods=['get'])
    def gallery(self, request, pk=None):
        """Get gallery for specific camp with permission check"""
        # Check camp access first (user is already authenticated)
        if not user_has_camp_access(request.user, pk):
            return Response(
                {"error": "You don't have access to this camp"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        camp = self.get_object()
        galleries = Gallery.objects.filter(camp=camp)
        
        # Apply additional filters
        type_param = request.query_params.get('type')
        if type_param:
            galleries = galleries.filter(type=type_param)
        
        serializer = GallerySerializer(galleries, many=True, context={'request': request})
        return Response(serializer.data)


class UpdateViewSet(viewsets.ModelViewSet):
    queryset = Update.objects.all()
    serializer_class = UpdateSerializer
    
    def get_queryset(self):
        queryset=Update.objects.all()
        camp_id = self.request.query_params.get('camp_id')
        if camp_id:
            queryset = queryset.filter(camp_id=camp_id)
        return queryset
    
    # def perform_create(self, serializer):
    #     serializer.save(author=self.request.user)
        
# Add this to views.py
@method_decorator(csrf_exempt, name='dispatch')
class StudentViewSet(viewsets.ModelViewSet):
    queryset = Student.objects.all()
    serializer_class = StudentSerializer
    permission_classes = [permissions.IsAuthenticated] 
    authentication_classes=[TokenAuthentication]
    
    def create(self, request, *args, **kwargs):
    # Get the camp_id from the URL
        camp_id = self.kwargs.get('camp_id')
        if camp_id:
            # Add the camp_id to the request data
            request.data['camp'] = camp_id
        return super().create(request, *args, **kwargs)

    def get_queryset(self):
        queryset = Student.objects.all()
        print(queryset)
        # Filter by camp if provided
        camp_id = self.kwargs.get('camp_id') or self.request.query_params.get('camp_id')
        print(camp_id)
        if camp_id:
            # Check if user has access to this camp
            if not user_has_camp_access(self.request.user, camp_id):
                return Student.objects.none()
            queryset = queryset.filter(camp=camp_id)
        else:
            # Filter by user's accessible camps
            accessible_camps = get_user_accessible_camps(self.request.user)
            queryset = queryset.filter(camp__in=accessible_camps)
        
        # Apply other filters
        standard = self.request.query_params.get('standard')
        if standard:
            queryset = queryset.filter(standard=standard)
        
        return queryset

    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context
    
# views.py
class TestPaperViewSet(viewsets.ModelViewSet):
    queryset = TestPaper.objects.all()
    serializer_class = TestPaperSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    authentication_classes=[TokenAuthentication]
    pagination_class = StandardResultsSetPagination
    
    def update(self, request, *args, **kwargs):
        partial = True  # Allow partial updates
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)
    
    def get_queryset(self):
        queryset = TestPaper.objects.all().order_by('-exam_date')  # Default sort by latest first
        
        
        # Apply filters
        if self.request.user.is_authenticated:
            accessible_camps = get_user_accessible_camps(self.request.user)
            queryset = queryset.filter(camp__in=accessible_camps)
            
        # Filter by type
        test_type = self.request.query_params.get('type')
        if test_type:
            queryset = queryset.filter(type=test_type)
        
        # Filter by camp
        camp_id = self.request.query_params.get('camp_id')
        if camp_id:
            queryset = queryset.filter(camp_id=camp_id)
            
        # Search by title
        search_query = self.request.query_params.get('search')
        if search_query:
            queryset = queryset.filter(
                Q(title__icontains=search_query) | 
                Q(description__icontains=search_query)
            )
            
        # Apply sorting
        sort_by = self.request.query_params.get('sort_by', 'exam_date')
        sort_order = self.request.query_params.get('sort_order', 'desc')
        
        # Validate sort_by field
        valid_sort_fields = ['title', 'exam_date', 'type', 'created_at']
        if sort_by not in valid_sort_fields:
            sort_by = 'exam_date'  # Default sort field
            
        # Apply sort direction
        if sort_order.lower() == 'asc':
            queryset = queryset.order_by(sort_by)
        else:
            queryset = queryset.order_by(f'-{sort_by}')
            
        return queryset
    
    def create(self, request, *args, **kwargs):
        # Handle file upload and other data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        test_paper = self.get_object()
        if not test_paper.file:
            return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
        
        file_path = test_paper.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)

class TestResultViewSet(viewsets.ModelViewSet):
    queryset = TestResult.objects.all()
    serializer_class = TestResultSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    authentication_classes=[TokenAuthentication]
    pagination_class = StandardResultsSetPagination
    
    def update(self, request, *args, **kwargs):
        partial = True  # Allow partial updates
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)
    
    def get_queryset(self):
        queryset = TestResult.objects.all().order_by('-result_date')  # Default sort by latest first
        
        # Apply filters
        
        if self.request.user.is_authenticated:
            accessible_camps = get_user_accessible_camps(self.request.user)
            queryset = queryset.filter(camp__in=accessible_camps)
            
        # Filter by type
        test_type = self.request.query_params.get('type')
        if test_type:
            queryset = queryset.filter(type=test_type)
        
        # Filter by camp
        camp_id = self.request.query_params.get('camp_id')
        if camp_id:
            queryset = queryset.filter(camp_id=camp_id)
            
        # Search by title
        search_query = self.request.query_params.get('search')
        if search_query:
            queryset = queryset.filter(
                Q(title__icontains=search_query) | 
                Q(description__icontains=search_query)
            )
            
        # Apply sorting
        sort_by = self.request.query_params.get('sort_by', 'result_date')
        sort_order = self.request.query_params.get('sort_order', 'desc')
        
        # Validate sort_by field
        valid_sort_fields = ['title', 'result_date', 'type', 'created_at']
        if sort_by not in valid_sort_fields:
            sort_by = 'result_date'  # Default sort field
            
        # Apply sort direction
        if sort_order.lower() == 'asc':
            queryset = queryset.order_by(sort_by)
        else:
            queryset = queryset.order_by(f'-{sort_by}')
            
        return queryset
    
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        test_result = self.get_object()
        if not test_result.file:
            return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
        
        file_path = test_result.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)


@permission_classes([permissions.IsAuthenticated])
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return Response({'message': 'Logout successful'})
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['POST', 'PUT'])
@permission_classes([permissions.IsAuthenticatedOrReadOnly])
def update_register(request):
    try:
        from django.utils import timezone
        from datetime import datetime
        from django.contrib.auth.models import User
        from .models import Update, Camp
        from .serializers import UpdateSerializer

        camp_id = request.data.get('camp')
        camp = Camp.objects.get(id=camp_id)

        # Get the author (using admin as fallback)
        try:
            author = User.objects.get(username='admin')
        except User.DoesNotExist:
            return Response({'error': 'Admin user not found'}, status=400)

        # Create or update the Update object
        if request.method == 'PUT':
            update_id = request.GET.get('id')
            try:
                update = Update.objects.get(id=update_id)
            except Update.DoesNotExist:
                return Response({'error': 'Update not found'}, status=404)
        else:  # POST
            update = Update()
            update.author = author

        # Set common fields
        update.camp = camp
        update.title = request.data.get('title', '')
        update.text = request.data.get('text', '')
        update.venue = request.data.get('venue', '')

        # Handle date and time if provided
        if 'examDate' in request.data and 'examTime' in request.data:
            date_str = request.data.get('examDate')
            time_str = request.data.get('examTime')
            if date_str and time_str:
                try:
                    naive_datetime = datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M')
                    aware_datetime = timezone.make_aware(naive_datetime)
                    update.time = aware_datetime
                except ValueError as e:
                    print(f"Error parsing date/time: {e}")

        # Save and serialize
        update.save()
        serializer = UpdateSerializer(update)
        return Response(serializer.data, status=200 if request.method == 'PUT' else 201)

    except Exception as e:
        import traceback
        print(f"Error in update_register: {str(e)}")
        print(traceback.format_exc())
        return Response({'error': str(e)}, status=500)
