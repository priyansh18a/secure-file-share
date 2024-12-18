from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser
from django.utils.crypto import get_random_string
from cryptography.fernet import Fernet

from app_backend.settings import MASTER_KEY

class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('user', 'Regular User'),
        ('guest', 'Guest'),
    ]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')
    id =          models.UUIDField(primary_key = True, default = uuid.uuid4, editable = False)
    otp_base32 =  models.CharField(max_length = 200, null = True)
    logged_in =   models.BooleanField(default = False)
   
    def __str__(self):
        return str(self.username)

class File(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='files/')
    name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    content_type = models.CharField(max_length=100, null=True, blank=True)

class EncryptedFileKey(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE)  # Link to your file
    encrypted_key = models.BinaryField()  # Encrypted encryption key
    iv = models.BinaryField()  # Initialization vector
    created_at = models.DateTimeField(auto_now_add=True)

    def encrypt_key(self, key: bytes):
        """ Encrypt the key before storing it in the database """
        fernet = Fernet(MASTER_KEY)  # Master key used for encrypting/decrypting
        self.encrypted_key = fernet.encrypt(key)
        self.save()

    def decrypt_key(self):
        """ Decrypt the stored key """
        fernet = Fernet(MASTER_KEY)
        return fernet.decrypt(self.encrypted_key)

def generate_access_token():
    """Generate a 64-character random string for file access tokens."""
    return get_random_string(64)

class FilePermission(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name="permissions")
    user_email_list = models.JSONField(default=list, blank=True)  # For regular user emails
    guest_email_list = models.JSONField(default=list, blank=True)  # For guest emails
    expiration_date = models.DateTimeField(null=True, blank=True)
    access_token = models.CharField(
        max_length=64,
        unique=True,
        default=generate_access_token  # Specify length
    ) 

