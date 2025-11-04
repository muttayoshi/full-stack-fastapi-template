import logging

from sqlmodel import Session

from app.core.db import engine, init_db
from app.items.models import Item  # noqa: F401

# Import all models to ensure SQLModel relationships are properly initialized
from app.users.models import User  # noqa: F401

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init() -> None:
    with Session(engine) as session:
        init_db(session)


def main() -> None:
    logger.info("Creating initial data")
    init()
    logger.info("Initial data created")


if __name__ == "__main__":
    main()
