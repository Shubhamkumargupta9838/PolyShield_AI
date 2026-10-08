import os
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from backend.app.core.config import settings
from backend.app.core.security_config import security_settings
from backend.app.core.logging import logger
from backend.app.core.exceptions import (
    PolyShieldException,
    ScanNotFoundException,
    InvalidStateTransitionException,
    InvalidPEFileException,
    FileTooLargeException,
    EmptyFileException,
    StaticAnalysisFailedException,
    PathTraversalException,
    ModelIntegrityException,
    AuthenticationException,
    AuthorizationException
)
from backend.app.db.mongodb import connect_to_mongo, close_mongo_connection
from backend.app.api.health import router as health_router
from backend.app.api.auth import router as auth_router
from backend.app.api.scans import router as scans_router
from backend.app.api.reports import router as reports_router
from backend.app.api.dynamic_analysis import router as dynamic_analysis_router
from backend.app.api.ensemble_router import router as ensemble_router
from backend.app.api.explanation_router import router as explanation_router

# Rate Limiter setup
limiter = Limiter(key_func=get_remote_address, default_limits=[security_settings.RATE_LIMIT_DEFAULT])


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.PROJECT_NAME} backend service v{settings.VERSION}")
    settings.validate_production_config()
    security_settings.validate_production_security(settings.ENVIRONMENT, settings.DEBUG)
    await connect_to_mongo()
    yield
    await close_mongo_connection()
    logger.info(f"Shutting down {settings.PROJECT_NAME} backend service")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Powered Polymorphic Malware Detection & Analysis Platform",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Mount static files directory for self-hosted docs & UI assets
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Custom self-hosted Swagger UI & ReDoc routes compliant with CSP (no inline scripts, no external CDNs)
if settings.DEBUG or settings.ENVIRONMENT.lower() != "production":
    @app.get("/docs", include_in_schema=False)
    async def custom_swagger_ui_html():
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>PolyShield AI - Swagger UI</title>
    <link rel="shortcut icon" href="/static/swagger-ui/favicon-32x32.png">
    <link rel="stylesheet" type="text/css" href="/static/swagger-ui/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="/static/swagger-ui/swagger-ui-bundle.js"></script>
    <script src="/static/swagger-ui/swagger-ui-standalone-preset.js"></script>
    <script src="/static/swagger-ui/swagger-initializer.js"></script>
</body>
</html>"""
        return HTMLResponse(content=html)

    @app.get("/redoc", include_in_schema=False)
    async def custom_redoc_html():
        html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"/>
    <title>PolyShield AI - ReDoc</title>
    <link rel="shortcut icon" href="/static/swagger-ui/favicon-32x32.png">
    <style>body { margin: 0; padding: 0; }</style>
</head>
<body>
    <div id="redoc-container"></div>
    <script src="/static/swagger-ui/redoc.standalone.js"></script>
    <script src="/static/swagger-ui/redoc-initializer.js"></script>
</body>
</html>"""
        return HTMLResponse(content=html)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    favicon_path = os.path.join(os.path.dirname(__file__), "static", "swagger-ui", "favicon-32x32.png")
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path)
    return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"message": "Not Found"})


# Configure CORS Middleware (Explicit origins only, no unrestricted wildcards with credentials)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


# HTTP Security Headers & Request Correlation Middleware
@app.middleware("http")
async def security_and_correlation_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:12]}"
    request.state.request_id = request_id

    response = await call_next(request)

    response.headers["X-Request-ID"] = request_id
    if security_settings.ENABLE_SECURITY_HEADERS:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = security_settings.CONTENT_SECURITY_POLICY
        if settings.ENVIRONMENT.lower() == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


# Custom Security & Domain Exception Handlers
@app.exception_handler(AuthenticationException)
async def authentication_exception_handler(request: Request, exc: AuthenticationException):
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error_code": exc.error_code,
            "message": exc.message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        headers={"WWW-Authenticate": "Bearer"}
    )


@app.exception_handler(AuthorizationException)
async def authorization_exception_handler(request: Request, exc: AuthorizationException):
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "error_code": exc.error_code,
            "message": exc.message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


@app.exception_handler(PathTraversalException)
async def path_traversal_handler(request: Request, exc: PathTraversalException):
    logger.warning(f"SECURITY_POLICY_VIOLATION: Path traversal blocked on {request.url.path}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error_code": exc.error_code,
            "message": exc.message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


@app.exception_handler(ModelIntegrityException)
async def model_integrity_handler(request: Request, exc: ModelIntegrityException):
    logger.critical(f"SECURITY_POLICY_VIOLATION: Model integrity failure on {request.url.path}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error_code": exc.error_code,
            "message": exc.message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


@app.exception_handler(ScanNotFoundException)
async def scan_not_found_handler(request: Request, exc: ScanNotFoundException):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error_code": exc.error_code,
            "message": exc.message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": {"scan_id": exc.scan_id}
        }
    )


@app.exception_handler(InvalidStateTransitionException)
async def invalid_state_transition_handler(request: Request, exc: InvalidStateTransitionException):
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={
            "error_code": exc.error_code,
            "message": exc.message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": {
                "current_status": exc.current_status,
                "target_status": exc.target_status
            }
        }
    )


@app.exception_handler(InvalidPEFileException)
@app.exception_handler(FileTooLargeException)
@app.exception_handler(EmptyFileException)
@app.exception_handler(PolyShieldException)
async def generic_polyshield_handler(request: Request, exc: PolyShieldException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error_code": exc.error_code,
            "message": exc.message,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


@app.exception_handler(Exception)
async def global_unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Internal Server Error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error_code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred. Internal stack trace suppressed for security.",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


# Register Routers
app.include_router(health_router, prefix=settings.API_V1_PREFIX)
app.include_router(auth_router, prefix=settings.API_V1_PREFIX)
app.include_router(scans_router, prefix=settings.API_V1_PREFIX)
app.include_router(reports_router, prefix=settings.API_V1_PREFIX)
app.include_router(dynamic_analysis_router, prefix=settings.API_V1_PREFIX)
app.include_router(ensemble_router, prefix=settings.API_V1_PREFIX)
app.include_router(explanation_router, prefix=settings.API_V1_PREFIX)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG
    )
