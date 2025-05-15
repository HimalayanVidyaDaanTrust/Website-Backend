from django.http import HttpResponseForbidden
from django.urls import resolve

class ApprovalCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if the user is trying to access admin-only endpoints
        path = request.path_info
        
        # Skip for authentication endpoints and public endpoints
        public_paths = [
            '/api/login/',
            '/api/register/',
            '/api/csrf/',
            '/api/gallery-list/',
            '/api/brochures/',
            '/api/reports/',
            '/api/',
            '/admin/login/',
        ]
        
        # Skip middleware for public paths or if path starts with static
        if any(path.startswith(p) for p in public_paths) or path.startswith('/static/'):
            return self.get_response(request)
        
        # Check if this is an admin-only path
        admin_paths = [
            '/api/approval-requests/',
            '/admin/',
        ]
        
        if any(path.startswith(p) for p in admin_paths):
            # Check if user is authenticated
            if not request.user.is_authenticated:
                return HttpResponseForbidden("Authentication required")
            
            # If user is superuser, allow access
            if request.user.is_superuser:
                return self.get_response(request)
            
            # Check user's role and approval status
            try:
                # Check if user is a Coordinator (has all access)
                if hasattr(request.user, 'profile') and request.user.profile.role == 'Coordinator':
                    return self.get_response(request)
                
                # For Slot Coordinators, check if they're approved
                if hasattr(request.user, 'approval_request'):
                    if request.user.approval_request.status == 'approved':
                        return self.get_response(request)
                    else:
                        return HttpResponseForbidden("Your account is pending approval")
                else:
                    return HttpResponseForbidden("Approval request not found")
            except:
                return HttpResponseForbidden("Access denied")
        
        # For all other requests, continue normally
        return self.get_response(request)