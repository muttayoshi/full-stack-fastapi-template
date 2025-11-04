"""Common schemas used across multiple domains."""

from typing import Generic, TypeVar

from pydantic import BaseModel, Field
from sqlmodel import SQLModel

# Generic type for data field
DataT = TypeVar("DataT")


class BaseResponse(BaseModel, Generic[DataT]):
    """
    Standardized API response schema.

    **Attributes:**
    - **code**: HTTP status code (200, 201, 400, 404, etc.)
    - **message**: Human-readable message describing the operation result
    - **data**: The actual response data (type varies by endpoint)

    **Usage Examples:**

    **Success - Get by ID:**
    ```json
    {
        "code": 200,
        "message": "User retrieved successfully",
        "data": {"id": "...", "name": "John Doe", ...}
    }
    ```

    **Success - List:**
    ```json
    {
        "code": 200,
        "message": "Users retrieved successfully",
        "data": [{"id": "...", "name": "John"}, {"id": "...", "name": "Jane"}]
    }
    ```

    **Success - Create:**
    ```json
    {
        "code": 201,
        "message": "User created successfully",
        "data": {"id": "123e4567-e89b-12d3-a456-426614174000"}
    }
    ```

    **Success - Update:**
    ```json
    {
        "code": 200,
        "message": "User updated successfully",
        "data": null
    }
    ```

    **Success - Delete:**
    ```json
    {
        "code": 200,
        "message": "User deleted successfully",
        "data": null
    }
    ```

    **Error:**
    ```json
    {
        "code": 404,
        "message": "User not found",
        "data": null
    }
    ```
    """

    code: int = Field(
        description="HTTP status code (200, 201, 400, 404, etc.)",
        examples=[200, 201, 400, 404, 500],
    )
    message: str = Field(
        description="Human-readable message describing the operation result",
        examples=[
            "Operation successful",
            "Resource created successfully",
            "Resource not found",
        ],
    )
    data: DataT | None = Field(
        default=None,
        description="The actual response data. Type varies by endpoint. Can be null for update/delete operations.",
    )


class ListResponse(BaseModel, Generic[DataT]):
    """
    Standardized API response schema for list endpoints with pagination.

    **Attributes:**
    - **code**: HTTP status code (200, 201, 400, 404, etc.)
    - **message**: Human-readable message describing the operation result
    - **data**: List of items
    - **count**: Total count of items (for pagination)

    **Usage Example:**
    ```json
    {
        "code": 200,
        "message": "Users retrieved successfully",
        "data": [
            {"id": "...", "name": "John"},
            {"id": "...", "name": "Jane"}
        ],
        "count": 2
    }
    ```
    """

    code: int = Field(
        description="HTTP status code",
        examples=[200],
    )
    message: str = Field(
        description="Human-readable message describing the operation result",
        examples=["Resources retrieved successfully"],
    )
    data: list[DataT] = Field(
        default_factory=list,
        description="List of items",
    )
    count: int = Field(
        description="Total count of items (useful for pagination)",
        examples=[10, 100, 1000],
    )


class CreatedResponse(BaseModel):
    """
    Standardized response for resource creation.

    **Usage Example:**
    ```json
    {
        "code": 201,
        "message": "User created successfully",
        "data": {"id": "123e4567-e89b-12d3-a456-426614174000"}
    }
    ```
    """

    code: int = Field(
        default=201,
        description="HTTP status code for creation",
    )
    message: str = Field(
        description="Success message",
        examples=["Resource created successfully"],
    )
    data: dict[str, str] = Field(
        description="Object containing the ID of the created resource",
        examples=[{"id": "123e4567-e89b-12d3-a456-426614174000"}],
    )


class UpdateDeleteResponse(BaseModel):
    """
    Standardized response for update and delete operations.

    **Usage Examples:**

    **Update:**
    ```json
    {
        "code": 200,
        "message": "User updated successfully",
        "data": null
    }
    ```

    **Delete:**
    ```json
    {
        "code": 200,
        "message": "User deleted successfully",
        "data": null
    }
    ```
    """

    code: int = Field(
        default=200,
        description="HTTP status code",
    )
    message: str = Field(
        description="Success message",
        examples=["Resource updated successfully", "Resource deleted successfully"],
    )
    data: None = Field(
        default=None,
        description="Always null for update/delete operations",
    )


# Generic message schema
class Message(SQLModel):
    """Generic message response schema."""

    message: str


"""Common package - Contains shared/generic models and schemas used across the application."""


__all__ = [
    "Message",
]
