import base64
from datetime import timedelta
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view   
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import *
from .services import *
from .models import *
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny  
from rest_framework.exceptions import AuthenticationFailed
from django.utils.timezone import now, timedelta


class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({'message': 'User created successfully', "user_id": user.id}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        user = getLoginUserService(request)
        if user == None:
            return Response({
				"status": "Login failed", 
				"message": f"No user with the corresponding username and password exists"
				}, 
				status=status.HTTP_400_BAD_REQUEST)
        return Response({ 'user_id': user.id })

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        data = serializer.data
        data.pop('otp_base32', None)
        return Response(data)

class Set2FAView(APIView):
	def post(self, request):
		"""
		Get the user, create a auth_url for them and convert it to a QR code using Node, the image is returned
		here and displayed in the frontend
		"""
		user = getUserService(request)
		if user == None:
			return Response({"status": "Used id is invalid", "message": f"No user with the corresponding user id exists" }, 
				status=status.HTTP_404_NOT_FOUND)
		
		qr_code = getQRCodeService(user)
		return Response({"qr_code": qr_code})

class Verify2FAView(APIView):
    def post(self, request):
        """
        Get the user, take the OTP associated with them, and verify it against the entered OTP.
        """
        user = getUserService(request)
        if user is None:
            return Response(
                {
                    "status": "Verification failed",
                    "message": "No user with the corresponding user ID exists"
                },
                status=status.HTTP_404_NOT_FOUND
            )

        valid_otp = getOTPValidityService(user, request.data.get('otp'))
        if not valid_otp:
            return Response(
                {
                    "status": "Verification failed",
                    "message": "OTP is invalid or already used"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        is_admin = user.is_staff  # True if the user is an admin/staff

        return Response(
            {
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
                "otp_verified": True,
                "isAdmin": is_admin  # Include the isAdmin flag
            }
        )
    
class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get("refresh_token")
        print(refresh_token)
        if not refresh_token:
            raise AuthenticationFailed("Refresh token is required")

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            return Response({"access_token": access_token})
        except Exception as e:
            raise AuthenticationFailed("Invalid or expired refresh token")

    def get(self, request):
        return Response({"message": "Welcome, Guest!"})

class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        Admin Dashboard - Fetch all users and uploaded files
        """
        # Check if the logged-in user is an admin
        if not request.user.is_staff:  # 'is_staff' identifies admin users
            return Response(
                {"detail": "Access denied. Admins only."}, 
                status=403
            )

        # Get all users and files
        users = User.objects.all().values("id", "username", "email", "is_active", "date_joined")
        files = File.objects.all().values("id", "name", "owner__username", "uploaded_at")

        # Return data in response
        return Response({
            "users": list(users),
            "files": list(files),
        })

class FileSavingView(APIView):
    parser_classes = [MultiPartParser]  # Handles file uploads
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Get the uploaded file
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return Response({"error": "No file provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        max_file_size = 5 * 1024 * 1024  # 5 MB in bytes
        if uploaded_file.size > max_file_size:
            return Response({"error": "File size exceeds the 5 MB limit."}, status=status.HTTP_400_BAD_REQUEST)
        
        iv = request.data.get('iv') 
        key = request.data.get('key') 

        if not key or not iv:
            return Response({"error": "Encryption key and IV must be provided."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            key = base64.b64decode(key)
            iv = base64.b64decode(iv)
        except Exception as e:
            return Response({"error": "Invalid base64 encoding for key or IV."}, status=status.HTTP_400_BAD_REQUEST)
        
        print(len(key))
        print(len(iv))
        if len(key) != 32:
            return Response({"error": "Invalid encryption key length. It must be 32 bytes."}, status=status.HTTP_400_BAD_REQUEST)

        if len(iv) != 16:
            return Response({"error": "Invalid IV length. It must be 16 bytes."}, status=status.HTTP_400_BAD_REQUEST)
        
        file_name = request.data.get('name', uploaded_file.name)
        content_type = request.data.get('content_type') or 'application/octet-stream'

        # Save the file instance
        file_instance = File.objects.create(
            owner=request.user,
            file=uploaded_file,
            name=file_name,
            uploaded_at=now(),
            content_type=content_type
        )

        file_key = EncryptedFileKey(file=file_instance)
        file_key.encrypt_key(key)  # Encrypt and save the key
        file_key.iv = iv  # Save IV used for encryption
        file_key.save()

        return Response({"message": "File uploaded successfully", "file_id": file_instance.id}, status=status.HTTP_201_CREATED)
    
class FileSharingView(APIView):
    def post(self, request, file_id):
        print(request.data)
        print(file_id)
        user_email_list = request.data.get("user_email_list", [])  # Regular user emails
        guest_email_list = request.data.get("guest_email_list", [])  # Guest emails
        expiration_minutes = 2880  # Expiration time in minutes (default: 2 days)

        if not user_email_list and not guest_email_list:
            return Response({
                "error": "At least one email (regular user or guest) must be provided to share the file."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate file existence
        file = get_object_or_404(File, id=file_id)

        # Update or create file permissions
        file_permission, created = FilePermission.objects.get_or_create(file=file)

        file_permission.user_email_list = list(set(file_permission.user_email_list + user_email_list))  # Deduplicate
        file_permission.guest_email_list = list(set(file_permission.guest_email_list + guest_email_list))  

        # Set expiration time
        expiration_date = now() + timedelta(minutes=expiration_minutes)
        file_permission.expiration_date = expiration_date

        # Generate a new access token for sharing 
        file_permission.access_token = get_random_string(length=64)
        file_permission.save()

        # Generate shareable link
        shareable_link = f"{request.build_absolute_uri('/api/files/')}{file_id}/access/?file_access_token={file_permission.access_token}"

        return Response({
            "message": "File shared successfully",
            "shareable_link": shareable_link,
            "expires_at": expiration_date
        }, status=status.HTTP_200_OK)

class FileAccessView(APIView):
    def get(self, request, file_id):
        file_access_token = request.query_params.get("file_access_token")
        if not file_access_token:
            return Response({"error": "File access token is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the file permission exists and validate token
        file_permission = FilePermission.objects.filter(file_id=file_id, access_token=file_access_token).first()
        if not file_permission:
            return Response({"error": "Invalid or expired file access token."}, status=status.HTTP_403_FORBIDDEN)

        # Check for token expiration
        if file_permission.expiration_date and file_permission.expiration_date < now():
            return Response({"error": "The file access token has expired."}, status=status.HTTP_403_FORBIDDEN)

        # Check user/guest permissions
        if not request.user.is_authenticated:
            # Guest user access
            guest_email = request.query_params.get("guest_email")
            if not guest_email:
                return Response({"error": "Guest email is required"}, status=status.HTTP_400_BAD_REQUEST)

            if guest_email not in file_permission.guest_email_list:
                return Response({"error": "Invalid email or no access to the file."}, status=status.HTTP_403_FORBIDDEN)
        else:
            # Authenticated user access
            user_email = request.user.email
            if user_email not in file_permission.user_email_list and user_email != file_permission.file.owner.email:
                if user_email in file_permission.guest_email_list:
                    # If the email is found in guest_email_list, return the file with the correct permissions
                    pass
                else:
                    return Response({"error": "You do not have permission to access this file."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch and return the file
        file = file_permission.file
        try:
            with open(file.file.path, "rb") as f:
                file_content = f.read()
        except File.DoesNotExist:
            return Response({"error": "File not found."}, status=status.HTTP_404_NOT_FOUND)

        filename = file.file.name.split("/")[-1]  # Extract filename from the path
        content_type = file.content_type or "application/octet-stream"

        # Serve file using HttpResponse
        response = HttpResponse(file_content, content_type=content_type)
        response["Content-Disposition"] = f"inline; filename={filename}"  # Open file inline
        return response

class FileAccessViewForFlag(APIView):
    def get(self, request, file_id):
        file_access_token = request.query_params.get("file_access_token")
        if not file_access_token:
            return Response({"error": "File access token is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the file permission exists and validate token
        file_permission = FilePermission.objects.filter(file_id=file_id, access_token=file_access_token).first()
        if not file_permission:
            return Response({"error": "Invalid or expired file access token."}, status=status.HTTP_403_FORBIDDEN)

        # Check for token expiration
        if file_permission.expiration_date and file_permission.expiration_date < now():
            return Response({"error": "The file access token has expired."}, status=status.HTTP_403_FORBIDDEN)
        
        is_view_only = True if not request.user.is_authenticated else False

        # Check user/guest permissions
        if not request.user.is_authenticated:
            # Guest user access
            guest_email = request.query_params.get("guest_email")
            if not guest_email:
                return Response({"error": "Guest email is required"}, status=status.HTTP_400_BAD_REQUEST)

            if guest_email not in file_permission.guest_email_list:
                return Response({"error": "Invalid email or no access to the file."}, status=status.HTTP_403_FORBIDDEN)
        else:
            # Authenticated user access
            user_email = request.user.email
            if user_email not in file_permission.user_email_list and user_email != file_permission.file.owner.email:
                if user_email in file_permission.guest_email_list:
                    is_view_only = True
                else:
                    return Response({"error": "You do not have permission to access this file."}, status=status.HTTP_403_FORBIDDEN)
                
        file_key = EncryptedFileKey.objects.get(file=file_permission.file)
        key = file_key.decrypt_key()
        iv = file_key.iv

        # Encode key and iv to Base64 before returning in response
        encoded_key = base64.b64encode(key).decode('utf-8')
        encoded_iv = base64.b64encode(iv).decode('utf-8')

        # Return only the `is_view_only` flag and encoded key/iv
        return Response({
            "is_view_only": is_view_only,
            "key": encoded_key,
            "iv": encoded_iv
        })

class DeleteUserView(APIView):
    """"
    Only admin users can delete other users.
    """
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        user_id = request.query_params.get('user_id')

        if not user_id:
            return Response({"error": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user trying to delete is an admin
        if request.user.is_staff:
            # Prevent deletion of staff/admin users
            if user.is_staff or user.is_superuser:
                return Response({"error": "Cannot delete staff/admin user"}, status=status.HTTP_403_FORBIDDEN)

            user.delete()
            return Response({"message": "User deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({"error": "You do not have permission to delete users"}, status=status.HTTP_403_FORBIDDEN)


class DeleteFileView(APIView):
    """
    Class-based view to delete a file.
    Only the file owner or admin users can delete the file.
    """
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        file_id = request.query_params.get('fileId')

        if not file_id:
            return Response({"error": "File ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            file = File.objects.get(id=file_id)
        except File.DoesNotExist:
            return Response({"error": "File not found"}, status=status.HTTP_404_NOT_FOUND)

        # Check if the user is the file owner or admin
        if file.owner == request.user or request.user.is_staff:
            file.delete()
            return Response({"message": "File deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        else:
            return Response({"error": "You do not have permission to delete this file"}, status=status.HTTP_403_FORBIDDEN)


def home(request):
    return HttpResponse("Server is running")