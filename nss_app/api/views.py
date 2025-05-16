from rest_framework import viewsets, permissions, status, generics, renderers
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from django.contrib.auth.models import User
from django.db import IntegrityError
import traceback
import logging
from .models import Profile, Announcement, Download, Gallery, Brochure, Report, Contact,PYP,STP,WTP, PYR,STR,WTR,ApprovalRequest,Camp,Update,Student
from .serializers import (
    UserSerializer, UserRegisterSerializer, ProfileSerializer,ApprovalRequestSerializer,
    AnnouncementSerializer, DownloadSerializer, GallerySerializer,
    BrochureSerializer, ReportSerializer, ContactSerializer,PYPSerializer, STPSerializer,WTPSerializer,PYRSerializer,STRSerializer,WTRSerializer,CampSerializer,UpdateSerializer,StudentSerializer
)
from django.http import FileResponse, Http404, JsonResponse
from django.views import View
from urllib.parse import quote as urlquote
import os
from django.conf import settings
from rest_framework.decorators import action
from rest_framework.negotiation import BaseContentNegotiation
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

class AnnouncementViewSet(viewsets.ModelViewSet):
    queryset = Announcement.objects.all().order_by('-date_posted')
    serializer_class = AnnouncementSerializer
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            permission_classes = [permissions.AllowAny]
        else:
            permission_classes = [permissions.IsAdminUser]
        return [permission() for permission in permission_classes]

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


class PYPViewSet(viewsets.ModelViewSet):
    queryset = PYP.objects.all().order_by('-exam_date', '-created_at')
    serializer_class = PYPSerializer
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
        pyp_obj = self.get_object()
        file_path = pyp_obj.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
    
class PYPList(generics.ListCreateAPIView):
    queryset = PYP.objects.all()
    serializer_class = PYPSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class PYPDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = PYP.objects.all()
    serializer_class = PYPSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class PYPDownload(generics.RetrieveAPIView):
    queryset = PYP.objects.all()
    serializer_class = PYPSerializer
    permission_classes = [permissions.AllowAny]
    
    def retrieve(self, request, *args, **kwargs):
        pyp = self.get_object()
        if not pyp.file:
            raise Http404("File not found")
        
        try:
            response = FileResponse(pyp.file.open('rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{pyp.file.name.split("/")[-1]}"'
            return response
        except Exception as e:
            raise Http404(f"Error serving file: {str(e)}")


class STPViewSet(viewsets.ModelViewSet):
    queryset = STP.objects.all().order_by('-exam_date', '-created_at')
    serializer_class = STPSerializer
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
        stp_obj = self.get_object()
        file_path = stp_obj.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
    
class STPList(generics.ListCreateAPIView):
    queryset = STP.objects.all()
    serializer_class = STPSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class STPDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = STP.objects.all()
    serializer_class = STPSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class STPDownload(generics.RetrieveAPIView):
    queryset = STP.objects.all()
    serializer_class = STPSerializer
    permission_classes = [permissions.AllowAny]
    
    def retrieve(self, request, *args, **kwargs):
        stp = self.get_object()
        if not stp.file:
            raise Http404("File not found")
        
        try:
            response = FileResponse(stp.file.open('rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{stp.file.name.split("/")[-1]}"'
            return response
        except Exception as e:
            raise Http404(f"Error serving file: {str(e)}")


class WTPViewSet(viewsets.ModelViewSet):
    queryset = WTP.objects.all().order_by('-exam_date', '-created_at')
    serializer_class = WTPSerializer
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
        wtp_obj = self.get_object()
        file_path = wtp_obj.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
    
class WTPList(generics.ListCreateAPIView):
    queryset = WTP.objects.all()
    serializer_class = STPSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class WTPDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = WTP.objects.all()
    serializer_class = WTPSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class WTPDownload(generics.RetrieveAPIView):
    queryset = WTP.objects.all()
    serializer_class = WTPSerializer
    permission_classes = [permissions.AllowAny]
    
    def retrieve(self, request, *args, **kwargs):
        wtp = self.get_object()
        if not wtp.file:
            raise Http404("File not found")
        
        try:
            response = FileResponse(wtp.file.open('rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{wtp.file.name.split("/")[-1]}"'
            return response
        except Exception as e:
            raise Http404(f"Error serving file: {str(e)}")

class PYRViewSet(viewsets.ModelViewSet):
    queryset = PYR.objects.all().order_by('-result_date', '-created_at')
    serializer_class = PYRSerializer
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
        pyr_obj = self.get_object()
        file_path = pyr_obj.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
    
class PYRList(generics.ListCreateAPIView):
    queryset = PYR.objects.all()
    serializer_class = PYRSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class PYRDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = PYR.objects.all()
    serializer_class = PYRSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class PYRDownload(generics.RetrieveAPIView):
    queryset = PYR.objects.all()
    serializer_class = PYRSerializer
    permission_classes = [permissions.AllowAny]
    
    def retrieve(self, request, *args, **kwargs):
        pyr = self.get_object()
        if not pyr.file:
            raise Http404("File not found")
        
        try:
            response = FileResponse(pyr.file.open('rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{pyr.file.name.split("/")[-1]}"'
            return response
        except Exception as e:
            raise Http404(f"Error serving file: {str(e)}")


class STRViewSet(viewsets.ModelViewSet):
    queryset = STR.objects.all().order_by('-result_date', '-created_at')
    serializer_class = STRSerializer
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
        str_obj = self.get_object()
        file_path = str_obj.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
    
class STRList(generics.ListCreateAPIView):
    queryset = STR.objects.all()
    serializer_class = STRSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class STRDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = STR.objects.all()
    serializer_class = STRSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class STRDownload(generics.RetrieveAPIView):
    queryset = STR.objects.all()
    serializer_class = STRSerializer
    permission_classes = [permissions.AllowAny]
    
    def retrieve(self, request, *args, **kwargs):
        str = self.get_object()
        if not str.file:
            raise Http404("File not found")
        
        try:
            response = FileResponse(str.file.open('rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{str.file.name.split("/")[-1]}"'
            return response
        except Exception as e:
            raise Http404(f"Error serving file: {str(e)}")


class WTRViewSet(viewsets.ModelViewSet):
    queryset = WTR.objects.all().order_by('-result_date', '-created_at')
    serializer_class = WTRSerializer
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
        wtr_obj = self.get_object()
        file_path = wtr_obj.file.path
        if os.path.exists(file_path):
            content_type, _ = mimetypes.guess_type(file_path)
            if not content_type:
                content_type = 'application/octet-stream'
            
            response = FileResponse(open(file_path, 'rb'), content_type=content_type)
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)
    
class WTRList(generics.ListCreateAPIView):
    queryset = WTR.objects.all()
    serializer_class = WTRSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class WTRDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = WTR.objects.all()
    serializer_class = WTRSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

class WTRDownload(generics.RetrieveAPIView):
    queryset = WTR.objects.all()
    serializer_class = WTRSerializer
    permission_classes = [permissions.AllowAny]
    
    def retrieve(self, request, *args, **kwargs):
        wtr = self.get_object()
        if not wtr.file:
            raise Http404("File not found")
        
        try:
            response = FileResponse(wtr.file.open('rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{wtr.file.name.split("/")[-1]}"'
            return response
        except Exception as e:
            raise Http404(f"Error serving file: {str(e)}")

class CampViewSet(viewsets.ModelViewSet):
    queryset = Camp.objects.all().order_by('-year', 'state', 'city')
    serializer_class = CampSerializer
    
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
    
    def perform_create(self, serializer):
        serializer.save(author=self.request.user)
        
# Add this to views.py
class StudentViewSet(viewsets.ModelViewSet):
    queryset = Student.objects.all()
    serializer_class = StudentSerializer
    
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


# Simple view for API index
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def api_index(request):
    return Response({
        "endpoints": {
            "gallery": "/gallery/",
            "brochures": "/brochures/",
            "reports": "/reports/",
            "pyp": "/pyp/",
            "stp": "/stp/",
            "wtp": "/wtp/",
            "pyr": "/pyr/",
            "str": "/str/",
            "wtr": "/wtr/",
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
    """
    API endpoint for student registration
    """
    # Add the registration date if not provided
    if 'registration_date' not in request.data:
        from datetime import date
        request.data['registration_date'] = date.today().isoformat()
        
    serializer = StudentSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
