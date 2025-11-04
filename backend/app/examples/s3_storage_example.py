"""
Example usage of Amazon S3 Storage integration.

This file demonstrates how to use the AmazonS3Storage class
for file upload, download, and management operations.
"""

from app.core.storage import AmazonS3Storage


def example_upload_from_disk():
    """Example: Upload a file from disk to S3."""
    s3 = AmazonS3Storage()

    # Upload file
    url = s3.upload_file(
        file_path="/path/to/local/file.pdf",
        destination_blob_name="documents/my-document.pdf"
    )

    print(f"File uploaded to: {url}")

    # Generate presigned URL for secure access
    presigned_url = s3.convert_public_url_to_signed_url(
        s3_url=url,
        expiration_hours=24
    )

    print(f"Presigned URL (valid for 24 hours): {presigned_url}")


def example_upload_from_memory():
    """Example: Upload file content from memory to S3."""
    s3 = AmazonS3Storage()

    # Read file into memory
    with open("/path/to/local/file.pdf", "rb") as f:
        file_content = f.read()

    # Upload from memory
    url = s3.upload_file_from_memory(
        file_content=file_content,
        destination_blob_name="uploads/document.pdf",
        content_type="application/pdf"
    )

    print(f"File uploaded to: {url}")


def example_download_file():
    """Example: Download a file from S3 to local disk."""
    s3 = AmazonS3Storage()

    # Download file
    s3.download_file(
        source_blob_name="uploads/document.pdf",
        destination_file_path="/path/to/save/downloaded.pdf"
    )

    print("File downloaded successfully")


def example_list_files():
    """Example: List files in S3 bucket with a specific prefix."""
    s3 = AmazonS3Storage()

    # List all files in 'uploads/' folder
    files = s3.list_files(prefix="uploads/", max_keys=100)

    print(f"Found {len(files)} files:")
    for file in files:
        print(f"  - {file['name']} ({file['size']} bytes)")


def example_delete_file():
    """Example: Delete a file from S3."""
    s3 = AmazonS3Storage()

    # Delete file
    success = s3.delete_file(blob_name="uploads/old-document.pdf")

    if success:
        print("File deleted successfully")


def example_check_file_exists():
    """Example: Check if a file exists in S3."""
    s3 = AmazonS3Storage()

    # Check existence
    exists = s3.file_exists(blob_name="uploads/document.pdf")

    if exists:
        print("File exists")
    else:
        print("File not found")


def example_get_presigned_url():
    """Example: Get presigned URL for secure file access."""
    s3 = AmazonS3Storage()

    # Get presigned URL (for private files)
    presigned_url = s3.get_file_url(
        blob_name="private/sensitive-document.pdf",
        signed=True,
        expiration_hours=2
    )

    print(f"Presigned URL (valid for 2 hours): {presigned_url}")

    # Get public URL (for public files)
    public_url = s3.get_file_url(
        blob_name="public/image.jpg",
        signed=False
    )

    print(f"Public URL: {public_url}")


def example_extract_blob_name():
    """Example: Extract blob name from S3 URL."""
    url = "https://my-bucket.s3.us-east-1.amazonaws.com/uploads/document.pdf?presigned-params"

    blob_name = AmazonS3Storage.extract_blob_name_from_url(url)

    print(f"Blob name: {blob_name}")  # Output: "uploads/document.pdf"


def example_upload_json_data():
    """Example: Upload JSON data to S3."""
    import json
    from datetime import datetime

    s3 = AmazonS3Storage()

    # Create some JSON data
    data = {
        "id": "12345",
        "name": "Sample Data",
        "timestamp": datetime.now().isoformat(),
        "items": ["item1", "item2", "item3"]
    }

    # Convert to JSON string and encode
    json_content = json.dumps(data, indent=2).encode("utf-8")

    # Upload to S3
    url = s3.upload_file_from_memory(
        file_content=json_content,
        destination_blob_name="data/sample-data.json",
        content_type="application/json"
    )

    print(f"JSON data uploaded to: {url}")


def example_upload_image():
    """Example: Upload an image file to S3."""
    s3 = AmazonS3Storage()

    # Read image file
    with open("/path/to/image.jpg", "rb") as f:
        image_content = f.read()

    # Upload image
    url = s3.upload_file_from_memory(
        file_content=image_content,
        destination_blob_name="images/photo.jpg",
        content_type="image/jpeg"
    )

    print(f"Image uploaded to: {url}")


if __name__ == "__main__":
    print("Amazon S3 Storage Examples")
    print("=" * 50)

    # Run examples (uncomment to test)
    # example_upload_from_disk()
    # example_upload_from_memory()
    # example_download_file()
    # example_list_files()
    # example_delete_file()
    # example_check_file_exists()
    # example_get_presigned_url()
    # example_extract_blob_name()
    # example_upload_json_data()
    # example_upload_image()

    print("\nNote: Make sure to configure S3 credentials in .env file before running examples")

