import uuid

from sqlmodel import Session, func, select

from app.items.models import Item
from app.items.schemas import ItemCreate


def create_item(*, session: Session, item_in: ItemCreate, owner_id: uuid.UUID) -> Item:
    """Create a new item in the database."""
    db_item = Item.model_validate(item_in, update={"owner_id": owner_id})
    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item


def get_item_by_id(*, session: Session, item_id: uuid.UUID) -> Item | None:
    """Get an item by ID."""
    return session.get(Item, item_id)


def get_items(
    *, session: Session, skip: int = 0, limit: int = 100
) -> tuple[list[Item], int]:
    """Get all items with pagination."""
    count_statement = select(func.count()).select_from(Item)
    count = session.exec(count_statement).one()
    statement = select(Item).offset(skip).limit(limit)
    items = session.exec(statement).all()
    return list(items), count


def get_items_by_owner(
    *, session: Session, owner_id: uuid.UUID, skip: int = 0, limit: int = 100
) -> tuple[list[Item], int]:
    """Get items by owner with pagination."""
    count_statement = (
        select(func.count()).select_from(Item).where(Item.owner_id == owner_id)
    )
    count = session.exec(count_statement).one()
    statement = select(Item).where(Item.owner_id == owner_id).offset(skip).limit(limit)
    items = session.exec(statement).all()
    return list(items), count
