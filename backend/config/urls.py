from django.contrib import admin
from django.urls import path
from logs.views import upload_file

urlpatterns = [
    path("admin/", admin.site.urls),
    path("upload", upload_file),
]