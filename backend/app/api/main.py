from fastapi import APIRouter

from app.auditlog.routers import router as auditlog_router
from app.common.routers import file_router, upload_router
from app.common.routers import router as common_router
from app.items.routers import router as items_router
from app.users.routers import router as users_router

api_router = APIRouter()

# Include domain routers
api_router.include_router(users_router)
api_router.include_router(items_router)
api_router.include_router(common_router)
api_router.include_router(upload_router)
api_router.include_router(file_router)
api_router.include_router(auditlog_router, prefix="/audit-logs", tags=["audit-logs"])
