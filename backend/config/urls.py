from django.contrib import admin
from django.urls import path
from logs.views import upload_file
from logs.api import search_logs

urlpatterns = [
    path("admin/", admin.site.urls),
    path("upload", upload_file),
    path("logs", search_logs),
]