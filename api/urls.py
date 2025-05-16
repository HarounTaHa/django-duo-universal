from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    ProtectedResourceView,
    UserLoginView,
    UserLogoutView,
    DuoAuthStatusView,
    TokenObtainPairWithDuoView,
    DuoAuthInitView,
    VerifyDuoAuthView
)

urlpatterns = [
    path('protected-resource/', ProtectedResourceView.as_view(), name='protected-resource'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
    path('duo-status/', DuoAuthStatusView.as_view(), name='duo-status'),
    path('token/', TokenObtainPairWithDuoView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('init-duo/', DuoAuthInitView.as_view(), name='init_duo'),
    path('verify-duo/', VerifyDuoAuthView.as_view(), name='verify_duo'),
]