"""
URL configuration for file_sharing_app project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from file_sharing_app.views import *

urlpatterns = [
    path('', home),
    path('admin/', admin.site.urls),
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/profile/', UserProfileView.as_view(), name='profile'),
    path('api/set-two-factor-auth/', Set2FAView.as_view()),
    path('api/verify-two-factor-auth/', Verify2FAView.as_view()),
    path('api/token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('api/admin/data', AdminDashboardView.as_view(), name='admin_view'),
    path('api/admin/delete-user/', DeleteUserView.as_view(), name='delete_user'),
    path('api/admin/delete-file/', DeleteFileView.as_view(), name='delete_file'),
    path('api/files/upload/', FileSavingView.as_view(), name='upload_file'),
    path('api/files/<file_id>/share/', FileSharingView.as_view(), name='share_file'),
    path('api/files/<file_id>/access/', FileAccessView.as_view(), name='access_file'),
    path('api/files/<file_id>/flag/', FileAccessViewForFlag.as_view(), name='access_file')
]

if settings.DEBUG:
        urlpatterns += static(settings.MEDIA_URL,
                              document_root=settings.MEDIA_ROOT)


urlpatterns += staticfiles_urlpatterns()