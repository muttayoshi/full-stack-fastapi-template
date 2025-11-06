import logging
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic.networks import EmailStr

from app.api.deps import get_current_active_superuser
from app.common.schemas import BaseResponse, Message
from app.core.storage import AmazonS3Storage, BackblazeB2Storage, GoogleCloudStorage
from app.utils import generate_test_email, send_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/utils", tags=["utils"])
upload_router = APIRouter(prefix="/upload", tags=["upload"])
file_router = APIRouter(prefix="/file", tags=["file"])
sandbox_router = APIRouter(prefix="/sandbox", tags=["sandbox"])


@router.post(
    "/test-email/",
    dependencies=[Depends(get_current_active_superuser)],
    status_code=201,
)
def test_email(email_to: EmailStr) -> Message:
    """
    Test emails.
    """
    email_data = generate_test_email(email_to=email_to)
    send_email(
        email_to=email_to,
        subject=email_data.subject,
        html_content=email_data.html_content,
    )
    return Message(message="Test email sent")


@router.get("/health-check/")
async def health_check() -> bool:
    return True


@upload_router.post("/", response_model=BaseResponse[list[str]], status_code=201)
async def upload_files(
    files: list[UploadFile] = File(..., description="Multiple files to upload"),
) -> BaseResponse[list[str]]:
    """
    Upload multiple files to Google Cloud Storage.

    **Parameters:**
    - files: List of files to upload

    **Returns:**
    - List of URLs for the uploaded files

    **Example Response:**
    ```json
    {
        "code": 201,
        "message": "Files uploaded successfully",
        "data": [
            "https://storage.googleapis.com/bucket-name/file1.pdf",
            "https://storage.googleapis.com/bucket-name/file2.jpg"
        ]
    }
    ```
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    try:
        gcs_service = GoogleCloudStorage()
        uploaded_urls = []

        for file in files:
            # Generate unique filename
            file_extension = (
                file.filename.split(".")[-1] if "." in file.filename else ""
            )
            unique_filename = (
                f"{uuid.uuid4()}.{file_extension}"
                if file_extension
                else str(uuid.uuid4())
            )

            # Read file content
            file_content = await file.read()

            # Determine content type
            content_type = file.content_type or "application/octet-stream"

            # Upload to GCS
            destination_blob_name = f"uploads/{unique_filename}"
            url = gcs_service.upload_file_from_memory(
                file_content=file_content,
                destination_blob_name=destination_blob_name,
                content_type=content_type,
            )

            uploaded_urls.append(gcs_service.convert_public_url_to_signed_url(url))
            logger.info(f"Uploaded file: {file.filename} -> {url}")
            logger.info(
                f"Signed URL: {file.filename} -> {gcs_service.convert_public_url_to_signed_url(url)}"
            )

        return BaseResponse(
            code=201,
            message=f"{len(uploaded_urls)} file(s) uploaded successfully",
            data=uploaded_urls,
        )

    except ValueError as e:
        # Handle GCS bucket validation errors
        logger.error(f"GCS configuration error: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Storage configuration error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error uploading files: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to upload files: {str(e)}")


@upload_router.post("/b2/", response_model=BaseResponse[list[str]], status_code=201)
async def upload_files_to_b2(
    files: list[UploadFile] = File(..., description="Multiple files to upload"),
) -> BaseResponse[list[str]]:
    """
    Upload multiple files to Backblaze B2 Storage.

    **Parameters:**
    - files: List of files to upload

    **Returns:**
    - List of presigned URLs for the uploaded files

    **Example Response:**
    ```json
    {
        "code": 201,
        "message": "Files uploaded successfully",
        "data": [
            "https://s3.us-west-004.backblazeb2.com/bucket-name/uploads/file1.pdf?...",
            "https://s3.us-west-004.backblazeb2.com/bucket-name/uploads/file2.jpg?..."
        ]
    }
    ```
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    try:
        b2_service = BackblazeB2Storage()
        uploaded_urls = []

        for file in files:
            # Generate unique filename
            file_extension = (
                file.filename.split(".")[-1] if "." in file.filename else ""
            )
            unique_filename = (
                f"{uuid.uuid4()}.{file_extension}"
                if file_extension
                else str(uuid.uuid4())
            )

            # Read file content
            file_content = await file.read()

            # Determine content type
            content_type = file.content_type or "application/octet-stream"

            # Upload to B2
            destination_blob_name = f"uploads/{unique_filename}"
            url = b2_service.upload_file_from_memory(
                file_content=file_content,
                destination_blob_name=destination_blob_name,
                content_type=content_type,
            )

            # Generate presigned URL
            signed_url = b2_service.convert_public_url_to_signed_url(url)
            uploaded_urls.append(signed_url)
            logger.info(f"Uploaded file to B2: {file.filename} -> {url}")
            logger.info(f"Presigned URL: {file.filename} -> {signed_url}")

        return BaseResponse(
            code=201,
            message=f"{len(uploaded_urls)} file(s) uploaded successfully to Backblaze B2",
            data=uploaded_urls,
        )

    except ValueError as e:
        # Handle B2 configuration errors
        logger.error(f"B2 configuration error: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Storage configuration error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error uploading files to B2: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to upload files: {str(e)}")


@upload_router.post("/s3/", response_model=BaseResponse[list[str]], status_code=201)
async def upload_files_to_s3(
    files: list[UploadFile] = File(..., description="Multiple files to upload"),
) -> BaseResponse[list[str]]:
    """
    Upload multiple files to Amazon S3 Storage.

    **Parameters:**
    - files: List of files to upload

    **Returns:**
    - List of presigned URLs for the uploaded files

    **Example Response:**
    ```json
    {
        "code": 201,
        "message": "Files uploaded successfully to Amazon S3",
        "data": [
            "https://bucket-name.s3.us-east-1.amazonaws.com/uploads/file1.pdf?...",
            "https://bucket-name.s3.us-east-1.amazonaws.com/uploads/file2.jpg?..."
        ]
    }
    ```
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")

    try:
        s3_service = AmazonS3Storage()
        uploaded_urls = []

        for file in files:
            # Generate unique filename
            file_extension = (
                file.filename.split(".")[-1] if "." in file.filename else ""
            )
            unique_filename = (
                f"{uuid.uuid4()}.{file_extension}"
                if file_extension
                else str(uuid.uuid4())
            )

            # Read file content
            file_content = await file.read()

            # Determine content type
            content_type = file.content_type or "application/octet-stream"

            # Upload to S3
            destination_blob_name = f"uploads/{unique_filename}"
            url = s3_service.upload_file_from_memory(
                file_content=file_content,
                destination_blob_name=destination_blob_name,
                content_type=content_type,
            )

            # Generate presigned URL
            signed_url = s3_service.convert_public_url_to_signed_url(url)
            uploaded_urls.append(signed_url)
            logger.info(f"Uploaded file to S3: {file.filename} -> {url}")
            logger.info(f"Presigned URL: {file.filename} -> {signed_url}")

        return BaseResponse(
            code=201,
            message=f"{len(uploaded_urls)} file(s) uploaded successfully to Amazon S3",
            data=uploaded_urls,
        )

    except ValueError as e:
        # Handle S3 configuration errors
        logger.error(f"S3 configuration error: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Storage configuration error: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Error uploading files to S3: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to upload files: {str(e)}")


@file_router.get("/signed-url/", status_code=307)
async def get_signed_url(
    url: str = Query(..., description="Public GCS URL to convert to signed URL"),
    expiration_days: int = Query(
        1, ge=1, le=365, description="Number of days until the signed URL expires"
    ),
) -> RedirectResponse:
    """
    Convert a public GCS URL to a signed URL and redirect to it.

    **Parameters:**
    - url: Public GCS URL (e.g., https://storage.googleapis.com/bucket/path/file.jpg)
    - expiration_days: Number of days until the signed URL expires (default: 7, max: 365)

    **Returns:**
    - Redirects to the signed URL that can be accessed without authentication
    """
    if not url:
        raise HTTPException(status_code=400, detail="URL parameter is required")

    try:
        gcs_service = GoogleCloudStorage()
        signed_url = gcs_service.convert_public_url_to_signed_url(
            gcs_url=url, expiration_days=expiration_days
        )

        logger.info(f"Generated signed URL for: {url}")

        return RedirectResponse(url=signed_url, status_code=307)

    except ValueError as e:
        logger.error(f"Invalid URL format: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid URL: {str(e)}")
    except Exception as e:
        logger.error(f"Error generating signed URL: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Failed to generate signed URL: {str(e)}"
        )


@file_router.get("/b2-signed-url/", status_code=307)
async def get_b2_signed_url(
    url: str = Query(..., description="Public B2 URL to convert to presigned URL"),
    expiration_hours: int = Query(
        24, ge=1, le=168, description="Number of hours until the presigned URL expires"
    ),
) -> RedirectResponse:
    """
    Convert a public Backblaze B2 URL to a presigned URL and redirect to it.

    **Parameters:**
    - url: Public B2 URL (e.g., https://s3.us-west-004.backblazeb2.com/bucket/path/file.jpg)
    - expiration_hours: Number of hours until the presigned URL expires (default: 24, max: 168)

    **Returns:**
    - Redirects to the presigned URL that can be accessed without authentication
    """
    if not url:
        raise HTTPException(status_code=400, detail="URL parameter is required")

    try:
        b2_service = BackblazeB2Storage()
        presigned_url = b2_service.convert_public_url_to_signed_url(
            b2_url=url, expiration_hours=expiration_hours
        )

        logger.info(f"Generated presigned URL for B2: {url}")

        return RedirectResponse(url=presigned_url, status_code=307)

    except ValueError as e:
        logger.error(f"Invalid URL format: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid URL: {str(e)}")
    except Exception as e:
        logger.error(f"Error generating presigned URL: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Failed to generate presigned URL: {str(e)}"
        )


@file_router.get("/s3-signed-url/", status_code=307)
async def get_s3_signed_url(
    url: str = Query(..., description="Public S3 URL to convert to presigned URL"),
    expiration_hours: int = Query(
        24, ge=1, le=168, description="Number of hours until the presigned URL expires"
    ),
) -> RedirectResponse:
    """
    Convert a public Amazon S3 URL to a presigned URL and redirect to it.

    **Parameters:**
    - url: Public S3 URL (e.g., https://bucket-name.s3.us-east-1.amazonaws.com/path/file.jpg)
    - expiration_hours: Number of hours until the presigned URL expires (default: 24, max: 168)

    **Returns:**
    - Redirects to the presigned URL that can be accessed without authentication
    """
    if not url:
        raise HTTPException(status_code=400, detail="URL parameter is required")

    try:
        s3_service = AmazonS3Storage()
        presigned_url = s3_service.convert_public_url_to_signed_url(
            s3_url=url, expiration_hours=expiration_hours
        )

        logger.info(f"Generated presigned URL for S3: {url}")

        return RedirectResponse(url=presigned_url, status_code=307)

    except ValueError as e:
        logger.error(f"Invalid URL format: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid URL: {str(e)}")
    except Exception as e:
        logger.error(f"Error generating presigned URL: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Failed to generate presigned URL: {str(e)}"
        )


@sandbox_router.get("/chat/", response_class=HTMLResponse)
async def chat_demo() -> str:
    """
    Serve the WebSocket Chat Demo HTML for testing purposes.

    This endpoint serves a fully functional chat interface that can be used to test
    the WebSocket chat functionality without CORS issues.

    **Access:** http://localhost:8000/api/v1/sandbox/chat/

    **Features:**
    - Login with existing credentials
    - Create and join chat rooms
    - Send and receive real-time messages via WebSocket
    - Visual indicators for connection status

    **Default credentials:**
    - Email: admin@example.com
    - Password: changethis
    """
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSocket Chat Demo</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
            display: grid;
            grid-template-columns: 300px 1fr;
            height: 90vh;
        }

        .sidebar {
            background: #f8f9fa;
            padding: 20px;
            border-right: 1px solid #dee2e6;
            overflow-y: auto;
        }

        .main-chat {
            display: flex;
            flex-direction: column;
        }

        .header {
            background: #667eea;
            color: white;
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
        }

        .header h1 {
            font-size: 24px;
            margin-bottom: 5px;
        }

        .status {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            margin-top: 10px;
        }

        .status.connected {
            background: #28a745;
        }

        .status.disconnected {
            background: #dc3545;
        }

        .login-form {
            padding: 20px;
        }

        .login-form input {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #dee2e6;
            border-radius: 5px;
        }

        .login-form button {
            width: 100%;
            padding: 10px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }

        .login-form button:hover {
            background: #5568d3;
        }

        .rooms-list {
            margin-top: 20px;
        }

        .rooms-list h3 {
            font-size: 16px;
            margin-bottom: 10px;
            color: #495057;
        }

        .room-item {
            padding: 12px;
            margin-bottom: 8px;
            background: white;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.2s;
            border: 2px solid transparent;
        }

        .room-item:hover {
            background: #e9ecef;
        }

        .room-item.active {
            border-color: #667eea;
            background: #e7e9ff;
        }

        .room-item h4 {
            font-size: 14px;
            margin-bottom: 4px;
        }

        .room-item p {
            font-size: 12px;
            color: #6c757d;
        }

        .messages {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
            background: #f8f9fa;
        }

        .message {
            margin-bottom: 15px;
            animation: slideIn 0.3s ease;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .message.own {
            text-align: right;
        }

        .message-bubble {
            display: inline-block;
            max-width: 70%;
            padding: 12px 16px;
            border-radius: 18px;
            background: white;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }

        .message.own .message-bubble {
            background: #667eea;
            color: white;
        }

        .message-sender {
            font-weight: bold;
            font-size: 13px;
            margin-bottom: 4px;
            color: #495057;
        }

        .message.own .message-sender {
            color: #e9ecef;
        }

        .message-content {
            font-size: 14px;
            line-height: 1.4;
            word-wrap: break-word;
        }

        .message-time {
            font-size: 11px;
            color: #6c757d;
            margin-top: 4px;
        }

        .message.own .message-time {
            color: #e9ecef;
        }

        .input-area {
            padding: 20px;
            background: white;
            border-top: 1px solid #dee2e6;
            display: flex;
            gap: 10px;
        }

        .input-area input {
            flex: 1;
            padding: 12px;
            border: 2px solid #dee2e6;
            border-radius: 25px;
            font-size: 14px;
        }

        .input-area input:focus {
            outline: none;
            border-color: #667eea;
        }

        .input-area button {
            padding: 12px 30px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 25px;
            cursor: pointer;
            font-weight: bold;
            transition: all 0.2s;
        }

        .input-area button:hover {
            background: #5568d3;
            transform: scale(1.05);
        }

        .input-area button:disabled {
            background: #dee2e6;
            cursor: not-allowed;
            transform: scale(1);
        }

        .create-room-btn {
            width: 100%;
            padding: 10px;
            background: #28a745;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin-bottom: 15px;
            font-weight: bold;
        }

        .create-room-btn:hover {
            background: #218838;
        }

        .notification {
            padding: 8px 16px;
            background: #ffc107;
            color: #212529;
            border-radius: 20px;
            margin: 10px 20px;
            font-size: 13px;
            text-align: center;
            animation: slideIn 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <div class="login-form" id="loginForm">
                <h3>Login</h3>
                <input type="email" id="emailInput" placeholder="Email" value="admin@example.com">
                <input type="password" id="passwordInput" placeholder="Password" value="changethis">
                <button onclick="login()">Connect</button>
            </div>

            <div id="roomsSection" style="display:none;">
                <button class="create-room-btn" onclick="createRoom()">+ Create Room</button>
                <div class="rooms-list">
                    <h3>My Rooms</h3>
                    <div id="roomsList"></div>
                </div>
            </div>
        </div>

        <div class="main-chat">
            <div class="header">
                <h1>WebSocket Chat Demo</h1>
                <span class="status disconnected" id="statusBadge">Disconnected</span>
                <div style="margin-top: 10px; font-size: 14px;">
                    <span id="currentRoom">Select a room to start chatting</span>
                </div>
            </div>

            <div class="messages" id="messagesContainer">
                <div style="text-align: center; color: #6c757d; margin-top: 50px;">
                    <h2>Welcome to WebSocket Chat! 👋</h2>
                    <p>Login and select a room to start chatting</p>
                </div>
            </div>

            <div class="input-area">
                <input type="text" id="messageInput" placeholder="Type a message..." disabled
                       onkeypress="if(event.key==='Enter') sendMessage()">
                <button onclick="sendMessage()" id="sendBtn" disabled>Send</button>
            </div>
        </div>
    </div>

    <script>
        let ws = null;
        let token = null;
        let currentUserId = null;
        let currentRoomId = null;
        let rooms = [];

        // Automatically detect the current host and protocol
        const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:';
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        const API_URL = `${protocol}//${host}/api/v1`;
        const WS_URL = `${wsProtocol}//${host}/api/v1`;

        async function login() {
            const email = document.getElementById('emailInput').value;
            const password = document.getElementById('passwordInput').value;

            try {
                const response = await fetch(`${API_URL}/login/access-token`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `username=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}`
                });

                if (!response.ok) throw new Error('Login failed');

                const data = await response.json();
                token = data.access_token;

                // Parse token to check expiry
                try {
                    const tokenParts = token.split('.');
                    const payload = JSON.parse(atob(tokenParts[1]));
                    const expiryDate = new Date(payload.exp * 1000);
                    console.log('🔑 Token expires at:', expiryDate.toLocaleString());
                    console.log('⏰ Token valid for:', Math.round((payload.exp * 1000 - Date.now()) / 1000 / 60), 'minutes');
                } catch (e) {
                    console.warn('Could not parse token expiry:', e);
                }

                // Get current user
                const userResponse = await fetch(`${API_URL}/users/me`, {
                    headers: {'Authorization': `Bearer ${token}`}
                });
                const userData = await userResponse.json();
                currentUserId = userData.id;

                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('roomsSection').style.display = 'block';

                connectWebSocket();
                loadRooms();
            } catch (error) {
                alert('Login failed: ' + error.message);
            }
        }

        function isTokenExpired() {
            if (!token) return true;
            try {
                const tokenParts = token.split('.');
                const payload = JSON.parse(atob(tokenParts[1]));
                const expiryTime = payload.exp * 1000;
                const now = Date.now();
                return now >= expiryTime;
            } catch (e) {
                console.error('Error checking token expiry:', e);
                return true;
            }
        }

        function connectWebSocket() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                console.log('WebSocket already connected');
                return;
            }

            // Check if token is expired before connecting
            if (isTokenExpired()) {
                console.error('❌ Token is expired, cannot connect WebSocket');
                alert('Your session has expired. Please login again.');
                document.getElementById('loginForm').style.display = 'block';
                document.getElementById('roomsSection').style.display = 'none';
                token = null;
                return;
            }

            console.log('Connecting to WebSocket:', `${WS_URL}/chat/ws?token=${token.substring(0, 20)}...`);
            ws = new WebSocket(`${WS_URL}/chat/ws?token=${token}`);

            ws.onopen = () => {
                console.log('✅ WebSocket connected successfully');
                document.getElementById('statusBadge').className = 'status connected';
                document.getElementById('statusBadge').textContent = 'Connected';
            };

            ws.onmessage = (event) => {
                console.log('📨 Received raw:', event.data);
                const data = JSON.parse(event.data);
                console.log('📨 Received parsed:', data);

                if (data.type === 'message' && data.data) {
                    console.log('💬 Adding message to UI');
                    addMessage(data.data);
                } else if (data.type === 'user_joined' || data.type === 'user_left') {
                    console.log('👤 User event:', data.type);
                    addNotification(data.message);
                } else if (data.type === 'connected') {
                    console.log('🎉 Connection confirmed:', data.message);
                } else if (data.type === 'error') {
                    console.error('❌ WebSocket error:', data.message);
                    alert('Error: ' + data.message);
                }
            };

            ws.onerror = (error) => {
                console.error('❌ WebSocket error:', error);
                document.getElementById('statusBadge').className = 'status disconnected';
                document.getElementById('statusBadge').textContent = 'Error';
            };

            ws.onclose = (event) => {
                console.log('🔌 WebSocket disconnected. Code:', event.code, 'Reason:', event.reason);
                document.getElementById('statusBadge').className = 'status disconnected';
                document.getElementById('statusBadge').textContent = 'Disconnected';

                // Check if connection was rejected due to auth failure
                if (event.code === 1008) {
                    console.error('❌ Authentication failed - Token invalid or expired');
                    alert('Session expired or invalid. Please login again.');
                    // Reset to login screen
                    document.getElementById('loginForm').style.display = 'block';
                    document.getElementById('roomsSection').style.display = 'none';
                    token = null;
                    currentUserId = null;
                    currentRoomId = null;
                    return;
                }

                // Auto reconnect after 3 seconds for other close reasons
                setTimeout(() => {
                    if (token) {
                        console.log('🔄 Attempting to reconnect...');
                        connectWebSocket();
                    }
                }, 3000);
            };
        }

        async function loadRooms() {
            try {
                const response = await fetch(`${API_URL}/chat/rooms/my`, {
                    headers: {'Authorization': `Bearer ${token}`}
                });
                const data = await response.json();
                rooms = data.data;

                const roomsList = document.getElementById('roomsList');
                roomsList.innerHTML = '';

                rooms.forEach(room => {
                    const roomDiv = document.createElement('div');
                    roomDiv.className = 'room-item';
                    roomDiv.onclick = () => selectRoom(room);
                    roomDiv.innerHTML = `
                        <h4>${room.name}</h4>
                        <p>${room.member_count} members</p>
                    `;
                    roomsList.appendChild(roomDiv);
                });
            } catch (error) {
                console.error('Failed to load rooms:', error);
            }
        }

        async function createRoom() {
            const name = prompt('Enter room name:');
            if (!name) return;

            try {
                const response = await fetch(`${API_URL}/chat/rooms`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: name,
                        description: '',
                        is_private: false
                    })
                });

                if (response.ok) {
                    loadRooms();
                }
            } catch (error) {
                alert('Failed to create room: ' + error.message);
            }
        }

        async function selectRoom(room) {
            console.log('🏠 Selecting room:', room.name, 'ID:', room.id);

            if (!ws || ws.readyState !== WebSocket.OPEN) {
                console.error('❌ WebSocket not connected. State:', ws ? ws.readyState : 'null');
                alert('WebSocket not connected. Please wait...');
                return;
            }

            currentRoomId = room.id;

            // Update UI
            document.querySelectorAll('.room-item').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.room-item').forEach(el => {
                if (el.querySelector('h4').textContent === room.name) {
                    el.classList.add('active');
                }
            });

            document.getElementById('currentRoom').textContent = room.name;
            document.getElementById('messageInput').disabled = false;
            document.getElementById('sendBtn').disabled = false;

            // Join room via WebSocket
            console.log('📤 Sending join_room message');
            ws.send(JSON.stringify({
                type: 'join_room',
                room_id: room.id
            }));

            // Load messages
            try {
                console.log('📥 Loading messages for room:', room.id);
                const response = await fetch(`${API_URL}/chat/rooms/${room.id}/messages?limit=50`, {
                    headers: {'Authorization': `Bearer ${token}`}
                });
                const data = await response.json();
                console.log('📥 Loaded messages:', data.data.length);

                const container = document.getElementById('messagesContainer');
                container.innerHTML = '';

                data.data.reverse().forEach(msg => {
                    addMessage(msg, false);
                });

                container.scrollTop = container.scrollHeight;
            } catch (error) {
                console.error('❌ Failed to load messages:', error);
            }
        }

        function sendMessage() {
            const input = document.getElementById('messageInput');
            const content = input.value.trim();

            console.log('📤 Attempting to send message:', content);

            if (!content) {
                console.log('⚠️ Empty message, not sending');
                return;
            }

            if (!currentRoomId) {
                console.log('⚠️ No room selected');
                return;
            }

            if (!ws || ws.readyState !== WebSocket.OPEN) {
                console.error('❌ WebSocket not connected. State:', ws ? ws.readyState : 'null');
                alert('WebSocket not connected. Please wait...');
                return;
            }

            const message = {
                type: 'message',
                room_id: currentRoomId,
                content: content,
                message_type: 'text'
            };

            console.log('📤 Sending message:', message);
            ws.send(JSON.stringify(message));

            input.value = '';
        }

        function addMessage(msg, animate = true) {
            const container = document.getElementById('messagesContainer');
            const isOwn = msg.sender_id === currentUserId;

            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${isOwn ? 'own' : ''}`;
            if (!animate) messageDiv.style.animation = 'none';

            const time = new Date(msg.created_at).toLocaleTimeString();

            messageDiv.innerHTML = `
                <div class="message-bubble">
                    ${!isOwn ? `<div class="message-sender">${msg.sender_full_name || msg.sender_email}</div>` : ''}
                    <div class="message-content">${msg.content}</div>
                    <div class="message-time">${time}</div>
                </div>
            `;

            container.appendChild(messageDiv);
            container.scrollTop = container.scrollHeight;
        }

        function addNotification(message) {
            const container = document.getElementById('messagesContainer');
            const notif = document.createElement('div');
            notif.className = 'notification';
            notif.textContent = message;
            container.appendChild(notif);
            container.scrollTop = container.scrollHeight;
        }
    </script>
</body>
</html>"""
    return html_content
