from rest_framework import viewsets, permissions, status, generics, renderers
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
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
    """
    Custom permission to only allow coordinators to access the view.
    """
    def has_permission(self, request, view):
        try:
            return request.user.is_authenticated and request.user.profile.role == 'Coordinator'
        except:
            return False

class ApprovalRequestViewSet(viewsets.ModelViewSet):
    """
    ViewSet for approval requests.
    - Coordinators can view all and approve/reject
    - Slot Coordinators can only view their own
    """
    queryset = ApprovalRequest.objects.all().order_by('-created_at')
    serializer_class = ApprovalRequestSerializer
    
    def get_permissions(self):
        """
        - List/retrieve/update/approve/reject: Coordinator only
        - Others: Authenticated users
        """
        if self.action in ['list', 'retrieve', 'update', 'partial_update', 'approve', 'reject']:
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
        """
        Approve a request and update user's profile role
        """
        approval_request = self.get_object()
        if approval_request.status != 'pending':
            return Response({"error": "This request has already been processed"}, 
                            status=status.HTTP_400_BAD_REQUEST)
            
        approval_request.status = 'approved'
        approval_request.reviewed_by = request.user
        approval_request.review_comments = request.data.get('comments', '')
        approval_request.save()
        
        # Update user's profile role
        profile = Profile.objects.get(user=approval_request.user)
        profile.role = approval_request.requested_role
        profile.save()
        
        return Response({
            "message": f"User {approval_request.user.username} has been approved as {approval_request.requested_role}",
            "approval_request": ApprovalRequestSerializer(approval_request).data
        })
    
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """
        Reject a request
        """
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
    
    def get_object(self):
        # Create profile if it doesn't exist
        profile, created = Profile.objects.get_or_create(user=self.request.user)
        return profile

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
    
    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated()]
        return [permissions.AllowAny()]
    
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
    content_negotiation_class = IgnoreClientContentNegotiation

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated()]
        return [permissions.AllowAny()]
    
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
    content_negotiation_class = IgnoreClientContentNegotiation

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [permissions.IsAuthenticated()]
        return [permissions.AllowAny()]
    
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
    Endpoint to ensure a CSRF cookie is set for the client.
    This view doesn't actually return any meaningful content, but
    the ensure_csrf_cookie decorator will set the cookie.
    """
    response = JsonResponse({"success": "CSRF cookie set"})
    
    # Get the origin from the request
    origin = request.headers.get('Origin', '')
    
    # List of allowed origins
    allowed_origins = [
        'http://localhost:5174',
        'http://localhost:5173',
        'https://himalayanvidyadaan.org',
        'https://www.himalayanvidyadaan.org',
        'https://api.himalayanvidyadaan.org',
        'https://admin.himalayanvidyadaan.org'
    ]
    
    # Set CORS headers if origin is allowed
    if origin in allowed_origins:
        response["Access-Control-Allow-Origin"] = origin
        response["Access-Control-Allow-Credentials"] = "true"
        response["Access-Control-Allow-Headers"] = "Origin, X-Requested-With, Content-Type, Accept, Authorization, X-CSRFToken"
        response["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    
    return response

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
@ensure_csrf_cookie
def login_view(request):
    """
    Login view that accepts username/email and password,
    authenticates the user, and returns a token.
    """
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response({'error': 'Please provide both username and password'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Try to authenticate using username
    user = authenticate(username=username, password=password)
    
    # If authentication failed, check if username is actually an email
    if user is None:
        # Try to find a user with the given email
        try:
            user_with_email = User.objects.get(email=username)
            # If found, try to authenticate with their username
            user = authenticate(username=user_with_email.username, password=password)
        except User.DoesNotExist:
            # No user found with that email
            pass
    
    if user is not None:
        login(request, user)
        token, created = Token.objects.get_or_create(user=user)
        
        try:
            profile = Profile.objects.get(user=user)
            profile_data = {
                'role': profile.role,
                'entry_number': profile.entry_number,
                'mobile_number': profile.mobile_number,
                'webmail': profile.webmail
            }
        except Profile.DoesNotExist:
            profile_data = {}
        
        # Check approval status
        approval_status = "not_requested"
        can_access_admin = False
        review_comments = None
        
        try:
            approval_request = ApprovalRequest.objects.get(user=user)
            approval_status = approval_request.status
            can_access_admin = approval_status == 'approved'
            review_comments = approval_request.review_comments
        except ApprovalRequest.DoesNotExist:
            pass
        
        # Special case: If user is superuser or has role 'Coordinator', they can always access admin
        if user.is_superuser or (hasattr(user, 'profile') and user.profile.role == 'Coordinator'):
            can_access_admin = True
        
        response = Response({
            'token': token.key,
            'user_id': user.pk,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
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
    else:
        response = Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        # Add CORS headers to error response too
        origin = request.headers.get('Origin', '')
        allowed_origins = [
            'http://localhost:5174',
            'http://localhost:5173',
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

# Class-based views for direct API access
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
    permission_classes = [permissions.AllowAny]
    
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
    permission_classes = [AllowAny]
    
    def get_queryset(self):
        queryset = Camp.objects.all()
        
        # Filter by state
        state = self.request.query_params.get('state')
        if state:
            queryset = queryset.filter(state__iexact=state)
            
        # Filter by city
        city = self.request.query_params.get('city')
        if city:
            queryset = queryset.filter(city__iexact=city)
            
        # Filter by year
        year = self.request.query_params.get('year')
        if year:
            queryset = queryset.filter(year=year)
            
        return queryset
    
    @action(detail=True, methods=['get'])
    def gallery(self, request, pk=None):
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
    
    # def perform_create(self, serializer):
    #     serializer.save(author=self.request.user)
        
# Add this to views.py
@method_decorator(csrf_exempt, name='dispatch')
class StudentViewSet(viewsets.ModelViewSet):
    queryset = Student.objects.all()
    serializer_class = StudentSerializer
    permission_classes = [AllowAny] 
    def create(self, request, *args, **kwargs):
    # Get the camp_id from the URL
        camp_id = self.kwargs.get('camp_id')
        if camp_id:
            # Add the camp_id to the request data
            request.data['camp'] = camp_id
        return super().create(request, *args, **kwargs)

    def get_queryset(self):
        queryset = Student.objects.all()
        
        # Filter by camp if provided
        camp_id = self.request.query_params.get('camp_id')
        if camp_id:
            queryset = queryset.filter(camp_id=camp_id)
        
        # Filter by standard if provided
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
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        queryset = TestPaper.objects.all().order_by('-exam_date')  # Default sort by latest first
        
        # Apply filters
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
    pagination_class = StandardResultsSetPagination
    
    def get_queryset(self):
        queryset = TestResult.objects.all().order_by('-result_date')  # Default sort by latest first
        
        # Apply filters
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
    
    def create(self, request, *args, **kwargs):
        # Handle file upload and other data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
    
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



# Simple view for API index
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def api_index(request):
    return Response({
        "endpoints": {
            "gallery": "/gallery/",
            "brochures": "/brochures/",
            "reports": "/reports/",
            "admin": "/admin/",
        }
    })

def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return Response({'message': 'Logout successful'})
    return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def student_register(request):
    if 'registration_date' not in request.data:
        from datetime import date
        request.data['registration_date'] = date.today().isoformat()
    serializer = StudentSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def update_register(request):
    try:
        from django.utils import timezone
        from datetime import datetime
        from django.contrib.auth.models import User
        from .models import Update
        
        camp_id = request.data.get('camp')
        camp = Camp.objects.get(id=camp_id)        
        # Get the author (using admin as fallback)
        try:
            author = User.objects.get(username='admin')
        except User.DoesNotExist:
            return Response({'error': 'Admin user not found'}, status=400)

        # Create a new update object
        update = Update(
            camp=camp,
            title=request.data.get('title', ''),
            text=request.data.get('text', ''),
            author=author,
            venue=request.data.get('venue', '')
        )
        
        # Handle date and time if provided
        if 'examDate' in request.data and 'examTime' in request.data:
            date_str = request.data.get('examDate')
            time_str = request.data.get('examTime')
            
            if date_str and time_str:
                try:
                    # Parse the datetime
                    naive_datetime = datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M')
                    
                    # Make it timezone aware
                    aware_datetime = timezone.make_aware(naive_datetime)
                    
                    # Set the time field
                    update.time = aware_datetime
                except ValueError as e:
                    print(f"Error parsing date/time: {e}")
        
        # Save the update
        update.save()
        
        # Serialize and return the created update
        serializer = UpdateSerializer(update)
        return Response(serializer.data, status=201)
        
    except Exception as e:
        import traceback
        print(f"Error in update_register: {str(e)}")
        print(traceback.format_exc())
        return Response({'error': str(e)}, status=500)


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def upload_test_paper(request):
    """
    Upload a new test paper
    """
    print("Received data:", request.data)

    serializer = TestPaperSerializer(data=request.data,context={'request': request})
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def upload_test_result(request):
    """
    Upload a new test result
    """
    print("Received data:", request.data)
    
    serializer = TestResultSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def create_camp(request):
    """
    Create a new camp
    """
    try:
        # Create a new camp object from the request data
        serializer = CampSerializer(data=request.data)
        
        if serializer.is_valid():
            # Save the camp
            camp = serializer.save()
            
            # Return the created camp data
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            # Return validation errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        import traceback
        print(f"Error in create_camp: {str(e)}")
        print(traceback.format_exc())
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)