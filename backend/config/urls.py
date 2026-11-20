from django.contrib import admin
from django.urls import path
from logs.views import upload_file
from logs.api import search_logs, list_files
from logs.api import search_logs, list_files, stats
urlpatterns = [
    path("admin/", admin.site.urls),
    path("upload", upload_file),
    path("logs", search_logs),
    path("files", list_files),
    path("stats", stats),
]