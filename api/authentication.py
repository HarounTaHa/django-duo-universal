from rest_framework import authentication
from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication


class DuoJWTAuthentication(JWTAuthentication):
    """
    Custom JWT authentication class that also checks for Duo authentication status
    """

    def authenticate(self, request):
        # First, authenticate using JWT
        auth_result = super().authenticate(request)

        if auth_result is None:
            return None

        user, token = auth_result

        # Define paths that don't require Duo authentication
        duo_exempt_paths = [
            '/api/v1/init-duo/',
            '/api/v1/verify-duo/',
            '/api/v1/duo-status/',
        ]

        # Skip Duo authentication check for exempt paths
        if request.path in duo_exempt_paths:
            return auth_result

        # Check if the user has completed Duo authentication
        if not getattr(user, 'is_duo_authenticated', False):
            raise exceptions.PermissionDenied("Duo authentication required")

        return auth_result
