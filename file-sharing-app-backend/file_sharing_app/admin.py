from django.contrib import admin

# Register your models here.
from .models import *

admin.site.register(User)
admin.site.register(File)
admin.site.register(EncryptedFileKey)
admin.site.register(FilePermission )