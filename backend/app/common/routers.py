import logging
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import RedirectResponse
from pydantic.networks import EmailStr

from app.api.deps import get_current_active_superuser
from app.common.schemas import BaseResponse, Message
from app.core.storage import AmazonS3Storage, BackblazeB2Storage, GoogleCloudStorage
from app.utils import generate_test_email, send_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/utils", tags=["utils"])
upload_router = APIRouter(prefix="/upload", tags=["upload"])
file_router = APIRouter(prefix="/file", tags=["file"])


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
