import logging

import boto3
from botocore.exceptions import ClientError
from google.cloud import storage
from google.oauth2 import service_account

from app.core.config import settings

logger = logging.getLogger(__name__)


class GoogleCloudStorage:
    """Service for managing file uploads and retrieval from Google Cloud Storage."""

    def __init__(self):
        self.bucket_name = getattr(settings, "GCS_BUCKET_NAME", "default-bucket-name")

        # Initialize client with credentials if provided
        if settings.GOOGLE_APPLICATION_CREDENTIALS:
            credentials = service_account.Credentials.from_service_account_file(
                settings.GOOGLE_APPLICATION_CREDENTIALS
            )
            self.client = storage.Client(
                credentials=credentials, project=settings.GOOGLE_CLOUD_PROJECT
            )
        else:
            # Fall back to Application Default Credentials
            self.client = storage.Client(project=settings.GOOGLE_CLOUD_PROJECT)

        self.bucket = self.client.bucket(self.bucket_name)

        # Note: We don't validate bucket existence here to avoid requiring
        # storage.buckets.get permission. The bucket will be validated
        # when the first operation is performed.

    def upload_file(self, file_path: str, destination_blob_name: str) -> str:
        """
        Upload a file to Google Cloud Storage.

        Args:
            file_path: Path to the local file to upload
            destination_blob_name: Name to give the file in GCS

        Returns:
            Signed URL of the uploaded file (valid for 7 days)
        """
        try:
            blob = self.bucket.blob(destination_blob_name)

            # Upload the file
            blob.upload_from_filename(file_path)

            # Make the blob publicly readable if needed
            # blob.make_public()

            # Return the public URL
            url = f"https://storage.googleapis.com/{self.bucket_name}/{destination_blob_name}"
            logger.info(f"File uploaded successfully to {url}")
            return url
        except Exception as e:
            logger.error(f"Error uploading file to GCS: {str(e)}")
            raise e

    def upload_file_from_memory(
        self,
        file_content: bytes,
        destination_blob_name: str,
        content_type: str = "application/octet-stream",
    ) -> str:
        """
        Upload file content from memory to Google Cloud Storage.

        Args:
            file_content: File content as bytes
            destination_blob_name: Name to give the file in GCS
            content_type: MIME type of the content

        Returns:
            Public URL of the uploaded file
        """
        try:
            blob = self.bucket.blob(destination_blob_name)

            # Upload from memory
            blob.upload_from_string(file_content, content_type=content_type)

            # Generate a signed URL that's valid for 7 days
            # url = blob.generate_signed_url(
            #     version="v4",
            #     expiration=timedelta(days=7),
            #     method="GET",
            # )

            # Return the public URL
            url = f"https://storage.googleapis.com/{self.bucket_name}/{destination_blob_name}"

            logger.info(
                f"File uploaded from memory successfully to {destination_blob_name}"
            )
            return url
        except Exception as e:
            logger.error(f"Error uploading file from memory to GCS: {str(e)}")
            raise e

    def download_file(self, source_blob_name: str, destination_file_path: str) -> None:
        """
        Download a file from Google Cloud Storage.

        Args:
            source_blob_name: Name of the file in GCS
            destination_file_path: Local path to save the file
        """
        try:
            blob = self.bucket.blob(source_blob_name)
            blob.download_to_filename(destination_file_path)
            logger.info(
                f"File downloaded successfully from {source_blob_name} to {destination_file_path}"
            )
        except Exception as e:
            logger.error(f"Error downloading file from GCS: {str(e)}")
            raise e

    def get_file_url(
        self, blob_name: str, signed: bool = False, expiration_hours: int = 1
    ) -> str:
        """
        Generate a URL for a file in GCS.

        Args:
            blob_name: Name of the file in GCS
            signed: Whether to generate a signed URL for private files
            expiration_hours: Expiration time for signed URL (hours)

        Returns:
            URL to access the file
        """
        try:
            blob = self.bucket.blob(blob_name)

            if signed:
                # Generate a signed URL that expires
                from datetime import timedelta

                url = blob.generate_signed_url(
                    expiration=timedelta(hours=expiration_hours), method="GET"
                )
            else:
                # Generate public URL (requires the file to be publicly accessible)
                url = f"https://storage.googleapis.com/{self.bucket_name}/{blob_name}"

            return url
        except Exception as e:
            logger.error(f"Error generating file URL: {str(e)}")
            raise e

    def delete_file(self, blob_name: str) -> bool:
        """Delete a file from GCS."""
        try:
            blob = self.bucket.blob(blob_name)
            blob.delete()
            logger.info(f"File deleted: {blob_name}")
            return True
        except Exception as e:
            logger.error(f"Error deleting file: {str(e)}")
            raise

    def convert_public_url_to_signed_url(
        self, gcs_url: str, expiration_days: int = 1
    ) -> str:
        """
        Convert a public GCS URL to a signed URL.

        Args:
            gcs_url: Public GCS URL (e.g., https://storage.googleapis.com/bucket/path/file.jpg)
            expiration_days: Number of days until the signed URL expires (default: 7)

        Returns:
            Signed URL that can be accessed without authentication

        Example:
            >>> gcs = GoogleCloudStorage()
            >>> public_url = "https://storage.googleapis.com/asid-storage-dev/uploads/file.jpg"
            >>> signed_url = gcs.convert_public_url_to_signed_url(public_url)
        """
        try:
            # Extract blob name from URL
            # URL format: https://storage.googleapis.com/bucket-name/path/to/file.ext
            if "storage.googleapis.com" not in gcs_url:
                raise ValueError("Invalid GCS URL format")

            # Remove the base URL to get bucket and blob path
            url_parts = gcs_url.replace("https://storage.googleapis.com/", "").split(
                "/", 1
            )

            if len(url_parts) != 2:
                raise ValueError(
                    "Invalid GCS URL format. Expected: https://storage.googleapis.com/bucket/path"
                )

            bucket_name, blob_name = url_parts

            # Verify this is the correct bucket
            if bucket_name != self.bucket_name:
                logger.warning(
                    f"URL bucket '{bucket_name}' doesn't match configured bucket '{self.bucket_name}'"
                )

            # Get the blob
            blob = self.bucket.blob(blob_name)

            # Generate signed URL
            from datetime import timedelta

            signed_url = blob.generate_signed_url(
                version="v4",
                expiration=timedelta(days=expiration_days),
                method="GET",
            )

            logger.info(f"Generated signed URL for {blob_name}")
            return signed_url

        except Exception as e:
            logger.error(f"Error converting URL to signed URL: {str(e)}")
            raise e

    @staticmethod
    def extract_blob_name_from_url(gcs_url: str) -> str:
        """
        Extract blob name (file path) from a GCS URL.

        Args:
            gcs_url: GCS URL (public or signed)

        Returns:
            Blob name (path to file in bucket)

        Example:
            >>> url = "https://storage.googleapis.com/asid-storage-dev/uploads/file.jpg"
            >>> blob_name = GoogleCloudStorage.extract_blob_name_from_url(url)
            >>> print(blob_name)  # "uploads/file.jpg"
        """
        # Handle both public and signed URLs
        if "storage.googleapis.com" not in gcs_url:
            raise ValueError("Invalid GCS URL format")

        # Remove base URL and parameters
        base_url = gcs_url.split("?")[0]  # Remove query parameters if signed URL
        url_parts = base_url.replace("https://storage.googleapis.com/", "").split(
            "/", 1
        )

        if len(url_parts) != 2:
            raise ValueError("Invalid GCS URL format")

        _, blob_name = url_parts
        return blob_name


class BackblazeB2Storage:
    """Service for managing file uploads and retrieval from Backblaze B2 Storage.

    Backblaze B2 is S3-compatible, so we use boto3 client.
    """

    def __init__(self):
        self.bucket_name = getattr(settings, "B2_BUCKET_NAME", "default-bucket-name")

        # Initialize S3-compatible client for Backblaze B2
        self.client = boto3.client(
            "s3",
            endpoint_url=settings.B2_ENDPOINT_URL,
            aws_access_key_id=settings.B2_APPLICATION_KEY_ID,
            aws_secret_access_key=settings.B2_APPLICATION_KEY,
            region_name=settings.B2_REGION,
        )

    def upload_file(self, file_path: str, destination_blob_name: str) -> str:
        """
        Upload a file to Backblaze B2.

        Args:
            file_path: Path to the local file to upload
            destination_blob_name: Name to give the file in B2

        Returns:
            Public URL of the uploaded file
        """
        try:
            # Upload the file
            self.client.upload_file(file_path, self.bucket_name, destination_blob_name)

            # Generate public URL
            url = (
                f"{settings.B2_ENDPOINT_URL}/{self.bucket_name}/{destination_blob_name}"
            )
            logger.info(f"File uploaded successfully to {url}")
            return url
        except ClientError as e:
            logger.error(f"Error uploading file to B2: {str(e)}")
            raise e

    def upload_file_from_memory(
        self,
        file_content: bytes,
        destination_blob_name: str,
        content_type: str = "application/octet-stream",
    ) -> str:
        """
        Upload file content from memory to Backblaze B2.

        Args:
            file_content: File content as bytes
            destination_blob_name: Name to give the file in B2
            content_type: MIME type of the content

        Returns:
            Public URL of the uploaded file
        """
        try:
            # Upload from memory
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=destination_blob_name,
                Body=file_content,
                ContentType=content_type,
            )

            # Generate public URL
            url = (
                f"{settings.B2_ENDPOINT_URL}/{self.bucket_name}/{destination_blob_name}"
            )

            logger.info(
                f"File uploaded from memory successfully to {destination_blob_name}"
            )
            return url
        except ClientError as e:
            logger.error(f"Error uploading file from memory to B2: {str(e)}")
            raise e

    def download_file(self, source_blob_name: str, destination_file_path: str) -> None:
        """
        Download a file from Backblaze B2.

        Args:
            source_blob_name: Name of the file in B2
            destination_file_path: Local path to save the file
        """
        try:
            self.client.download_file(
                self.bucket_name, source_blob_name, destination_file_path
            )
            logger.info(
                f"File downloaded successfully from {source_blob_name} to {destination_file_path}"
            )
        except ClientError as e:
            logger.error(f"Error downloading file from B2: {str(e)}")
            raise e

    def get_file_url(
        self, blob_name: str, signed: bool = False, expiration_hours: int = 1
    ) -> str:
        """
        Generate a URL for a file in B2.

        Args:
            blob_name: Name of the file in B2
            signed: Whether to generate a presigned URL for private files
            expiration_hours: Expiration time for presigned URL (hours)

        Returns:
            URL to access the file
        """
        try:
            if signed:
                # Generate a presigned URL
                url = self.client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": self.bucket_name, "Key": blob_name},
                    ExpiresIn=expiration_hours * 3600,
                )
            else:
                # Generate public URL
                url = f"{settings.B2_ENDPOINT_URL}/{self.bucket_name}/{blob_name}"

            return url
        except ClientError as e:
            logger.error(f"Error generating file URL: {str(e)}")
            raise e

    def delete_file(self, blob_name: str) -> bool:
        """Delete a file from B2."""
        try:
            self.client.delete_object(Bucket=self.bucket_name, Key=blob_name)
            logger.info(f"File deleted: {blob_name}")
            return True
        except ClientError as e:
            logger.error(f"Error deleting file: {str(e)}")
            raise

    def convert_public_url_to_signed_url(
        self, b2_url: str, expiration_hours: int = 24
    ) -> str:
        """
        Convert a public B2 URL to a presigned URL.

        Args:
            b2_url: Public B2 URL
            expiration_hours: Number of hours until the presigned URL expires (default: 24)

        Returns:
            Presigned URL that can be accessed without authentication

        Example:
            >>> b2 = BackblazeB2Storage()
            >>> public_url = "https://s3.us-west-004.backblazeb2.com/my-bucket/uploads/file.jpg"
            >>> signed_url = b2.convert_public_url_to_signed_url(public_url)
        """
        try:
            # Extract blob name from URL
            blob_name = self.extract_blob_name_from_url(b2_url)

            # Generate presigned URL
            signed_url = self.client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket_name, "Key": blob_name},
                ExpiresIn=expiration_hours * 3600,
            )

            logger.info(f"Generated presigned URL for {blob_name}")
            return signed_url

        except Exception as e:
            logger.error(f"Error converting URL to presigned URL: {str(e)}")
            raise e

    @staticmethod
    def extract_blob_name_from_url(b2_url: str) -> str:
        """
        Extract blob name (file path) from a B2 URL.

        Args:
            b2_url: B2 URL (public or presigned)

        Returns:
            Blob name (path to file in bucket)

        Example:
            >>> url = "https://s3.us-west-004.backblazeb2.com/my-bucket/uploads/file.jpg"
            >>> blob_name = BackblazeB2Storage.extract_blob_name_from_url(url)
            >>> print(blob_name)  # "uploads/file.jpg"
        """
        # Handle both public and presigned URLs
        if "backblazeb2.com" not in b2_url:
            raise ValueError("Invalid B2 URL format")

        # Remove query parameters if presigned URL
        base_url = b2_url.split("?")[0]

        # Extract path after bucket name
        # URL format: https://s3.us-west-004.backblazeb2.com/bucket-name/path/to/file.ext
        url_parts = base_url.split("/")

        if len(url_parts) < 5:
            raise ValueError("Invalid B2 URL format")

        # Join everything after the bucket name
        blob_name = "/".join(url_parts[4:])
        return blob_name

    def list_files(self, prefix: str = "", max_keys: int = 1000) -> list[dict]:
        """
        List files in the B2 bucket.

        Args:
            prefix: Filter results to files that begin with this prefix
            max_keys: Maximum number of files to return

        Returns:
            List of file metadata dictionaries
        """
        try:
            response = self.client.list_objects_v2(
                Bucket=self.bucket_name, Prefix=prefix, MaxKeys=max_keys
            )

            files = []
            if "Contents" in response:
                for obj in response["Contents"]:
                    files.append(
                        {
                            "name": obj["Key"],
                            "size": obj["Size"],
                            "last_modified": obj["LastModified"],
                            "etag": obj["ETag"],
                        }
                    )

            logger.info(f"Listed {len(files)} files with prefix '{prefix}'")
            return files
        except ClientError as e:
            logger.error(f"Error listing files: {str(e)}")
            raise e

    def file_exists(self, blob_name: str) -> bool:
        """
        Check if a file exists in B2.

        Args:
            blob_name: Name of the file to check

        Returns:
            True if file exists, False otherwise
        """
        try:
            self.client.head_object(Bucket=self.bucket_name, Key=blob_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            else:
                logger.error(f"Error checking file existence: {str(e)}")
                raise e


class AmazonS3Storage:
    """Service for managing file uploads and retrieval from Amazon S3 Storage."""

    def __init__(self):
        self.bucket_name = getattr(settings, "S3_BUCKET_NAME", "default-bucket-name")
        self.region = getattr(settings, "S3_REGION", "us-east-1")

        # Initialize S3 client
        self.client = boto3.client(
            "s3",
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=self.region,
        )

    def upload_file(self, file_path: str, destination_blob_name: str) -> str:
        """
        Upload a file to Amazon S3.

        Args:
            file_path: Path to the local file to upload
            destination_blob_name: Name to give the file in S3

        Returns:
            Public URL of the uploaded file
        """
        try:
            # Upload the file
            self.client.upload_file(file_path, self.bucket_name, destination_blob_name)

            # Generate public URL
            url = f"https://{self.bucket_name}.s3.{self.region}.amazonaws.com/{destination_blob_name}"
            logger.info(f"File uploaded successfully to {url}")
            return url
        except ClientError as e:
            logger.error(f"Error uploading file to S3: {str(e)}")
            raise e

    def upload_file_from_memory(
        self,
        file_content: bytes,
        destination_blob_name: str,
        content_type: str = "application/octet-stream",
    ) -> str:
        """
        Upload file content from memory to Amazon S3.

        Args:
            file_content: File content as bytes
            destination_blob_name: Name to give the file in S3
            content_type: MIME type of the content

        Returns:
            Public URL of the uploaded file
        """
        try:
            # Upload from memory
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=destination_blob_name,
                Body=file_content,
                ContentType=content_type,
            )

            # Generate public URL
            url = f"https://{self.bucket_name}.s3.{self.region}.amazonaws.com/{destination_blob_name}"

            logger.info(
                f"File uploaded from memory successfully to {destination_blob_name}"
            )
            return url
        except ClientError as e:
            logger.error(f"Error uploading file from memory to S3: {str(e)}")
            raise e

    def download_file(self, source_blob_name: str, destination_file_path: str) -> None:
        """
        Download a file from Amazon S3.

        Args:
            source_blob_name: Name of the file in S3
            destination_file_path: Local path to save the file
        """
        try:
            self.client.download_file(
                self.bucket_name, source_blob_name, destination_file_path
            )
            logger.info(
                f"File downloaded successfully from {source_blob_name} to {destination_file_path}"
            )
        except ClientError as e:
            logger.error(f"Error downloading file from S3: {str(e)}")
            raise e

    def get_file_url(
        self, blob_name: str, signed: bool = False, expiration_hours: int = 1
    ) -> str:
        """
        Generate a URL for a file in S3.

        Args:
            blob_name: Name of the file in S3
            signed: Whether to generate a presigned URL for private files
            expiration_hours: Expiration time for presigned URL (hours)

        Returns:
            URL to access the file
        """
        try:
            if signed:
                # Generate a presigned URL
                url = self.client.generate_presigned_url(
                    "get_object",
                    Params={"Bucket": self.bucket_name, "Key": blob_name},
                    ExpiresIn=expiration_hours * 3600,
                )
            else:
                # Generate public URL
                url = f"https://{self.bucket_name}.s3.{self.region}.amazonaws.com/{blob_name}"

            return url
        except ClientError as e:
            logger.error(f"Error generating file URL: {str(e)}")
            raise e

    def delete_file(self, blob_name: str) -> bool:
        """Delete a file from S3."""
        try:
            self.client.delete_object(Bucket=self.bucket_name, Key=blob_name)
            logger.info(f"File deleted: {blob_name}")
            return True
        except ClientError as e:
            logger.error(f"Error deleting file: {str(e)}")
            raise

    def convert_public_url_to_signed_url(
        self, s3_url: str, expiration_hours: int = 24
    ) -> str:
        """
        Convert a public S3 URL to a presigned URL.

        Args:
            s3_url: Public S3 URL
            expiration_hours: Number of hours until the presigned URL expires (default: 24)

        Returns:
            Presigned URL that can be accessed without authentication

        Example:
            >>> s3 = AmazonS3Storage()
            >>> public_url = "https://my-bucket.s3.us-east-1.amazonaws.com/uploads/file.jpg"
            >>> signed_url = s3.convert_public_url_to_signed_url(public_url)
        """
        try:
            # Extract blob name from URL
            blob_name = self.extract_blob_name_from_url(s3_url)

            # Generate presigned URL
            signed_url = self.client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket_name, "Key": blob_name},
                ExpiresIn=expiration_hours * 3600,
            )

            logger.info(f"Generated presigned URL for {blob_name}")
            return signed_url

        except Exception as e:
            logger.error(f"Error converting URL to presigned URL: {str(e)}")
            raise e

    @staticmethod
    def extract_blob_name_from_url(s3_url: str) -> str:
        """
        Extract blob name (file path) from an S3 URL.

        Args:
            s3_url: S3 URL (public or presigned)

        Returns:
            Blob name (path to file in bucket)

        Example:
            >>> url = "https://my-bucket.s3.us-east-1.amazonaws.com/uploads/file.jpg"
            >>> blob_name = AmazonS3Storage.extract_blob_name_from_url(url)
            >>> print(blob_name)  # "uploads/file.jpg"
        """
        # Handle both public and presigned URLs
        if ".s3." not in s3_url and "s3.amazonaws.com" not in s3_url:
            raise ValueError("Invalid S3 URL format")

        # Remove query parameters if presigned URL
        base_url = s3_url.split("?")[0]

        # Extract path after bucket name
        # URL formats:
        # - https://bucket-name.s3.region.amazonaws.com/path/to/file.ext
        # - https://s3.region.amazonaws.com/bucket-name/path/to/file.ext
        if ".s3." in base_url:
            # Format: https://bucket-name.s3.region.amazonaws.com/path/to/file.ext
            url_parts = base_url.split("/", 3)
            if len(url_parts) < 4:
                raise ValueError("Invalid S3 URL format")
            blob_name = url_parts[3]
        else:
            # Format: https://s3.region.amazonaws.com/bucket-name/path/to/file.ext
            url_parts = base_url.split("/", 4)
            if len(url_parts) < 5:
                raise ValueError("Invalid S3 URL format")
            blob_name = url_parts[4]

        return blob_name

    def list_files(self, prefix: str = "", max_keys: int = 1000) -> list[dict]:
        """
        List files in the S3 bucket.

        Args:
            prefix: Filter results to files that begin with this prefix
            max_keys: Maximum number of files to return

        Returns:
            List of file metadata dictionaries
        """
        try:
            response = self.client.list_objects_v2(
                Bucket=self.bucket_name, Prefix=prefix, MaxKeys=max_keys
            )

            files = []
            if "Contents" in response:
                for obj in response["Contents"]:
                    files.append(
                        {
                            "name": obj["Key"],
                            "size": obj["Size"],
                            "last_modified": obj["LastModified"],
                            "etag": obj["ETag"],
                        }
                    )

            logger.info(f"Listed {len(files)} files with prefix '{prefix}'")
            return files
        except ClientError as e:
            logger.error(f"Error listing files: {str(e)}")
            raise e

    def file_exists(self, blob_name: str) -> bool:
        """
        Check if a file exists in S3.

        Args:
            blob_name: Name of the file to check

        Returns:
            True if file exists, False otherwise
        """
        try:
            self.client.head_object(Bucket=self.bucket_name, Key=blob_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            else:
                logger.error(f"Error checking file existence: {str(e)}")
                raise e


# Example usage in a transcription service:
def store_transcription_result_in_gcs(
    _self, transcription_id: str, result_data: dict
) -> str:
    """
    Store transcription result as JSON in Google Cloud Storage.

    Args:
        transcription_id: Unique ID for the transcription
        result_data: Transcription result data to store

    Returns:
        Public URL to the stored transcription
    """
    gcs_service = GoogleCloudStorage()

    # Convert result data to JSON string
    import json

    json_content = json.dumps(
        result_data, indent=2, default=str
    )  # default=str handles datetime objects

    # Create destination name
    destination_name = f"transcriptions/{transcription_id}.json"

    # Upload to GCS
    url = gcs_service.upload_file_from_memory(
        file_content=json_content.encode("utf-8"),
        destination_blob_name=destination_name,
        content_type="application/json",
    )

    return url
