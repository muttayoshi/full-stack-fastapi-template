import uuid

from sqlmodel import Session

from app.items.models import Item
from app.items.schemas import ItemCreate, ItemUpdate
from app.items import repositories


class ItemService:
    """Business logic for item operations."""

    @staticmethod
    def create_item(*, session: Session, item_in: ItemCreate, owner_id: uuid.UUID) -> Item:
        """Create a new item."""
        return repositories.create_item(session=session, item_in=item_in, owner_id=owner_id)

    @staticmethod
    def get_item_by_id(*, session: Session, item_id: uuid.UUID) -> Item | None:
        """Get an item by ID."""
        return repositories.get_item_by_id(session=session, item_id=item_id)

    @staticmethod
    def get_items(*, session: Session, skip: int = 0, limit: int = 100) -> tuple[list[Item], int]:
        """Get all items with pagination."""
        return repositories.get_items(session=session, skip=skip, limit=limit)

    @staticmethod
    def get_items_by_owner(
        *, session: Session, owner_id: uuid.UUID, skip: int = 0, limit: int = 100
    ) -> tuple[list[Item], int]:
        """Get items by owner with pagination."""
        return repositories.get_items_by_owner(
            session=session, owner_id=owner_id, skip=skip, limit=limit
        )

    @staticmethod
    def update_item(*, session: Session, item: Item, item_in: ItemUpdate) -> Item:
        """Update an existing item."""
        update_dict = item_in.model_dump(exclude_unset=True)
        item.sqlmodel_update(update_dict)
        session.add(item)
        session.commit()
        session.refresh(item)
        return item

    @staticmethod
    def delete_item(*, session: Session, item: Item) -> None:
        """Delete an item."""
        session.delete(item)
        session.commit()

