"""Pytest configuration and fixtures."""

import os

import pytest


# ---------------------------------------------------------------------------
# Environment isolation — must run before ANY test or import of src.*
# Prevents pydantic-settings from reading the production .env file.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _isolate_from_production_env():
    """Clear all production env vars before tests. Restores them on teardown."""
    prod_vars = [
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_BOT_USERNAME",
        "APPROVED_DIRECTORY",
        "ALLOWED_USERS",
        "TELEGRAM_ALLOWED_USERS",
        "DATABASE_URL",
        "ANTHROPIC_API_KEY",
    ]
    saved = {k: os.environ.pop(k, None) for k in prod_vars}
    os.environ["ENVIRONMENT"] = "testing"
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
    os.environ.pop("ENVIRONMENT", None)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_user_id():
    """Sample Telegram user ID for testing."""
    return 123456789


@pytest.fixture
def sample_config():
    """Sample configuration for testing."""
    return {
        "telegram_bot_token": "test_token",
        "telegram_bot_username": "test_bot",
        "approved_directory": "/tmp/test_projects",
        "allowed_users": [123456789],
    }
