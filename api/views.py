from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from .duo_universal_client import DuoUniversalClient
from .utils import standardized_response


class ProtectedResourceView(APIView):
    """
    A view that requires both Django authentication and Duo authentication.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return standardized_response(
            True,
            "Authentication successful",
            {
                "message": "You have successfully authenticated with both Django and Duo!",
                "user": request.user.username
            }
        )


class TokenObtainPairWithDuoView(TokenObtainPairView):
    """
    Custom token view that includes the Duo authentication status in the response.
    """

    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)

            if response.status_code == 200:
                # Include Duo authentication status in the response
                user = self.user
                data = response.data
                data['duo_authenticated'] = user.is_duo_authenticated
                if not user.is_duo_authenticated:
                    data['duo_auth_required'] = True

                return standardized_response(
                    True,
                    "Authentication successful",
                    data
                )
            else:
                # If there was an error in the parent method
                return standardized_response(
                    False,
                    "Authentication failed",
                    {},
                    response.status_code
                )
        except Exception as e:
            return standardized_response(
                False,
                str(e),
                {},
                status.HTTP_400_BAD_REQUEST
            )


class UserLoginView(APIView):
    """
    API view for user login with JWT.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response(
                {"error": "Please provide both username and password"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(username=username, password=password)

        if not user:
            return standardized_response(
                False,
                "Invalid credentials",
                {},
                status.HTTP_401_UNAUTHORIZED
            )
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)

        response_data = {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'duo_authenticated': user.is_duo_authenticated,
        }

        if not user.is_duo_authenticated:
            response_data['duo_auth_required'] = True

        return standardized_response(
            True,
            "Login successful",
            response_data
        )


class UserLogoutView(APIView):
    """
    API view for user logout - blacklists the token.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                # Blacklist the token to prevent its further use
                token.blacklist()

            # Reset Duo authentication status
            request.user.is_duo_authenticated = False
            request.user.save()

            return standardized_response(
                True,
                "Successfully logged out",
                {}
            )
        except Exception as e:
            return standardized_response(
                False,
                str(e),
                {},
                status.HTTP_400_BAD_REQUEST
            )


class DuoAuthStatusView(APIView):
    """
    API view to check Duo authentication status.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        duo_authenticated = request.user.is_duo_authenticated

        return standardized_response(
            True,
            "Duo authentication status retrieved",
            {
                "duo_authenticated": duo_authenticated
            }
        )


class DuoAuthInitView(APIView):
    """
    Initializes Duo Universal authentication for React frontend
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # User must be authenticated with Django but not yet with Duo
        if request.user.is_duo_authenticated:
            return standardized_response(
                True,
                "User is already authenticated with Duo",
                {}
            )

        # Initialize Duo client
        duo_client = DuoUniversalClient()

        # Generate authentication URL for the user
        try:
            auth_data = duo_client.generate_auth_url(request.user.username)

            return standardized_response(
                True,
                "Duo authentication initialized",
                {
                    "auth_url": auth_data['auth_url'],
                    "state": auth_data['state']
                }
            )
        except Exception as e:
            return standardized_response(
                False,
                str(e),
                {},
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VerifyDuoAuthView(APIView):
    """
    Verifies Duo Universal authentication response from React frontend
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        duo_code = request.data.get('duo_code')

        if not duo_code:
            return standardized_response(
                False,
                "Missing Duo authorization code",
                {},
                status.HTTP_400_BAD_REQUEST
            )

        # Initialize Duo client
        duo_client = DuoUniversalClient()

        # Verify the authorization code
        try:
            success = duo_client.exchange_authorization_code(duo_code, request.user.username)

            if not success:
                return standardized_response(
                    False,
                    "Duo authentication failed",
                    {},
                    status.HTTP_401_UNAUTHORIZED
                )

            # Mark the user as Duo authenticated
            request.user.is_duo_authenticated = True
            request.user.save()

            # Return new tokens with updated Duo status
            refresh = RefreshToken.for_user(request.user)

            return standardized_response(
                True,
                "Duo authentication successful",
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "duo_authenticated": True
                }
            )
        except Exception as e:
            return standardized_response(
                False,
                str(e),
                {},
                status.HTTP_500_INTERNAL_SERVER_ERROR
            )
