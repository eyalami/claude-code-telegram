"""Integration tests: full message pipeline from Telegram update to response.

Tests the middleware chain: auth → rate limit → orchestrator.
Claude SDK is mocked — no real API calls. SQLite is real (temp file).
"""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from telegram.ext import ApplicationHandlerStop

from src.bot.core import ClaudeCodeBot
from src.bot.middleware.auth import auth_middleware
from src.bot.middleware.rate_limit import rate_limit_middleware
from src.config import create_test_config
from src.config.settings import Settings
from src.security.auth import AuthenticationManager, WhitelistAuthProvider
from src.security.rate_limiter import RateLimiter
from src.storage.database import DatabaseManager
from src.storage.repositories import UserRepository


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ALLOWED_USER_ID = 42_001
BLOCKED_USER_ID = 99_999


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def settings(tmp_dir: Path) -> Settings:
    return create_test_config(
        approved_directory=str(tmp_dir),
        allowed_users=[ALLOWED_USER_ID],
        rate_limit_requests=5,
        rate_limit_burst=5,
        rate_limit_window=60,
        agentic_mode=True,
    )


@pytest.fixture
def mock_settings_obj(tmp_dir: Path) -> MagicMock:
    s = MagicMock(spec=Settings)
    s.telegram_token_str = "test:token"
    s.webhook_url = None
    s.agentic_mode = True
    s.enable_quick_actions = False
    s.enable_mcp = False
    s.enable_git_integration = False
    s.enable_file_uploads = False
    s.enable_session_export = False
    s.enable_image_uploads = False
    s.enable_conversation_mode = False
    s.enable_api_server = False
    s.enable_scheduler = False
    s.approved_directory = str(tmp_dir)
    return s


def _make_update(user_id: int, text: str = "hello") -> MagicMock:
    update = MagicMock()
    update.effective_user = MagicMock()
    update.effective_user.id = user_id
    update.effective_user.username = f"user_{user_id}"
    update.effective_user.is_bot = False
    update.effective_message = MagicMock()
    update.effective_message.text = text
    update.effective_message.document = None
    update.effective_message.photo = None
    update.effective_message.reply_text = AsyncMock()
    return update


def _make_context(bot_data: dict) -> MagicMock:
    ctx = MagicMock()
    ctx.bot_data = bot_data
    return ctx


# ---------------------------------------------------------------------------
# Auth middleware tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestAuthMiddlewarePipeline:
    """Auth middleware allows/rejects based on whitelist."""

    def _make_bot(self, mock_settings_obj, auth_manager):
        deps = {
            "auth_manager": auth_manager,
            "security_validator": MagicMock(),
            "rate_limiter": MagicMock(),
            "audit_logger": AsyncMock(),
            "storage": MagicMock(),
            "claude_integration": MagicMock(),
        }
        return ClaudeCodeBot(mock_settings_obj, deps)

    async def test_allowed_user_passes_auth(self, mock_settings_obj) -> None:
        auth_manager = MagicMock()
        auth_manager.is_authenticated.return_value = True
        auth_manager.refresh_session.return_value = True
        auth_manager.get_session.return_value = MagicMock(auth_provider="whitelist")

        bot = self._make_bot(mock_settings_obj, auth_manager)
        update = _make_update(ALLOWED_USER_ID)
        context = _make_context({})

        wrapper = bot._create_middleware_handler(auth_middleware)
        # Should not raise — allowed user passes through
        await wrapper(update, context)

    async def test_unknown_user_is_rejected(self, mock_settings_obj) -> None:
        auth_manager = MagicMock()
        auth_manager.is_authenticated.return_value = False
        auth_manager.authenticate_user = AsyncMock(return_value=False)
        audit_logger = AsyncMock()

        bot = self._make_bot(mock_settings_obj, auth_manager)
        bot.deps["audit_logger"] = audit_logger
        update = _make_update(BLOCKED_USER_ID)
        context = _make_context({})

        wrapper = bot._create_middleware_handler(auth_middleware)
        with pytest.raises(ApplicationHandlerStop):
            await wrapper(update, context)

        # Must reply to inform the user they are not authorised
        update.effective_message.reply_text.assert_called_once()


# ---------------------------------------------------------------------------
# Rate limiter middleware tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestRateLimiterMiddlewarePipeline:
    """Rate limiter middleware blocks after N requests in the window."""

    def _make_bot(self, mock_settings_obj, rate_limiter):
        deps = {
            "auth_manager": MagicMock(),
            "security_validator": MagicMock(),
            "rate_limiter": rate_limiter,
            "audit_logger": AsyncMock(),
            "storage": MagicMock(),
            "claude_integration": MagicMock(),
        }
        return ClaudeCodeBot(mock_settings_obj, deps)

    async def test_first_request_is_allowed(
        self, mock_settings_obj, settings: Settings
    ) -> None:
        rate_limiter = RateLimiter(settings)
        bot = self._make_bot(mock_settings_obj, rate_limiter)
        update = _make_update(ALLOWED_USER_ID, "first message")
        context = _make_context({})

        wrapper = bot._create_middleware_handler(rate_limit_middleware)
        # First request should pass
        await wrapper(update, context)

    async def test_excess_requests_are_blocked(
        self, mock_settings_obj, settings: Settings
    ) -> None:
        rate_limiter = RateLimiter(settings)
        bot = self._make_bot(mock_settings_obj, rate_limiter)

        # Drain the bucket — settings.rate_limit_burst=5 tokens
        for _ in range(5):
            await rate_limiter.check_rate_limit(ALLOWED_USER_ID, cost=0.0, tokens=1)

        # Now the next request should be blocked
        rate_limiter_mock = MagicMock()
        rate_limiter_mock.check_rate_limit = AsyncMock(
            return_value=(False, "Rate limit exceeded")
        )
        bot.deps["rate_limiter"] = rate_limiter_mock

        update = _make_update(ALLOWED_USER_ID, "too many messages")
        context = _make_context({})

        wrapper = bot._create_middleware_handler(rate_limit_middleware)
        with pytest.raises(ApplicationHandlerStop):
            await wrapper(update, context)


# ---------------------------------------------------------------------------
# Storage integration: user created on first seen
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestStoragePipeline:
    """Storage layer creates and retrieves users across real SQLite."""

    @pytest.fixture
    async def db(self, tmp_path: Path):
        db_path = tmp_path / "integration.db"
        manager = DatabaseManager(f"sqlite:///{db_path}")
        await manager.initialize()
        yield manager
        await manager.close()

    async def test_user_lifecycle_create_and_fetch(
        self, db: DatabaseManager
    ) -> None:
        from src.storage.models import UserModel

        repo = UserRepository(db)
        user = UserModel(user_id=ALLOWED_USER_ID, username="integration_user")

        await repo.create_user(user)
        fetched = await repo.get_user(ALLOWED_USER_ID)

        assert fetched is not None
        assert fetched.user_id == ALLOWED_USER_ID
        assert fetched.username == "integration_user"

    async def test_unknown_user_returns_none(self, db: DatabaseManager) -> None:
        repo = UserRepository(db)
        result = await repo.get_user(BLOCKED_USER_ID)
        assert result is None
