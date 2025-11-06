from sqlmodel import Session, create_engine, select

from app.core.config import settings
from app.users.models import User
from app.users.schemas import UserCreate
from app.users.services import UserService

# Create engine with proper pool settings to prevent connection leaks
# pool_pre_ping ensures connections are alive before using them
# pool_size is the number of connections to keep open
# max_overflow allows temporary connections beyond pool_size
engine = create_engine(
    str(settings.SQLALCHEMY_DATABASE_URI),
    pool_pre_ping=True,  # Test connection before using to avoid stale connections
    pool_size=10,  # Number of permanent connections in the pool
    max_overflow=20,  # Max additional connections when pool is exhausted
    pool_recycle=3600,  # Recycle connections after 1 hour to avoid stale connections
    echo=False,  # Set to True for SQL query debugging
)


# make sure all SQLModel models are imported (app.models) before initializing DB
# otherwise, SQLModel might fail to initialize relationships properly
# for more details: https://github.com/fastapi/full-stack-fastapi-template/issues/28


def init_db(session: Session) -> None:
    # Tables should be created with Alembic migrations
    # But if you don't want to use migrations, create
    # the tables un-commenting the next lines
    # from sqlmodel import SQLModel

    # This works because the models are already imported and registered from app.models
    # SQLModel.metadata.create_all(engine)

    user = session.exec(
        select(User).where(User.email == settings.FIRST_SUPERUSER)
    ).first()
    if not user:
        user_in = UserCreate(
            email=settings.FIRST_SUPERUSER,
            password=settings.FIRST_SUPERUSER_PASSWORD,
            is_superuser=True,
        )
        user = UserService.create_user(session=session, user_create=user_in)
