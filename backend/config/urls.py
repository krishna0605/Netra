from django.conf import settings
from django.contrib import admin
from django.urls import include, path


urlpatterns = [
    path("api/", include("apps.forensics.urls")),
]

if settings.NETRA_DEPLOYMENT_PROFILE == "local":
    urlpatterns.append(path("admin/", admin.site.urls))
