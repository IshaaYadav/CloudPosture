"""Cloud Posture Scanner - FastAPI Application Entry Point."""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import aws, buckets, cis, health, instances, scans, storage
from app.config import get_settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cloud_posture_scanner")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown events."""
    settings = get_settings()
    logger.info("Initializing Cloud Posture Scanner backend...")
    logger.info(f"Target AWS Region: {settings.AWS_REGION}")
    logger.info(f"Report S3 Bucket: {settings.POSTURE_RESULTS_BUCKET}")
    logger.info(f"AWS Profile: {settings.AWS_PROFILE or '(Default Credential Chain)'}")
    yield
    logger.info("Shutting down Cloud Posture Scanner backend...")


app = FastAPI(
    title="Cloud Posture Scanner API",
    description=(
        "Production-grade AWS Cloud Security Posture Management (CSPM) API. "
        "Evaluates account resources against CIS AWS Foundations Benchmark checks "
        "and automatically archives audit reports into Amazon S3."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

settings = get_settings()

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch unhandled exceptions and format friendly JSON error response."""
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": str(exc),
            "path": request.url.path,
        },
    )


# Include all API route modules
app.include_router(health.router)
app.include_router(aws.router)
app.include_router(storage.router)
app.include_router(instances.router)
app.include_router(buckets.router)
app.include_router(cis.router)
app.include_router(scans.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

