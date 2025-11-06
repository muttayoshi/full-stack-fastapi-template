from fastapi import APIRouter

from app.auditlog.routers import router as auditlog_router
from app.chat.routers import router as chat_router
from app.common.routers import file_router, sandbox_router, upload_router
from app.common.routers import router as common_router
from app.items.routers import router as items_router
from app.sites.routers import router as site_router
from app.users.routers import router as users_router

api_router = APIRouter()

# Include domain routers
api_router.include_router(users_router)
api_router.include_router(items_router)
api_router.include_router(common_router)
api_router.include_router(upload_router)
api_router.include_router(file_router)
api_router.include_router(sandbox_router)
api_router.include_router(site_router)
api_router.include_router(auditlog_router)
api_router.include_router(chat_router)
