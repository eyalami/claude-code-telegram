"""Critical-path sanity tests. Fast, no external calls. Run before every deploy."""

import tempfile
from pathlib import Path

import pytest

from datetime import UTC, datetime, timedelta

from src.config import create_test_config
from src.security.auth import DatabaseAuthProvider, WhitelistAuthProvider
from src.security.rate_limiter import RateLimiter
from src.storage.database import DatabaseManager
from src.storage.models import InviteTokenModel, SessionModel, UserModel
from src.storage.repositories import InviteTokenRepository, SessionRepository, UserRepository


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@pytest.mark.sanity
class TestConfigSanity:
    def test_config_loads(self, tmp_path: Path) -> None:
        config = create_test_config(approved_directory=str(tmp_path))
        assert config is not None
        assert config.approved_directory == tmp_path

    def test_approved_directory_is_accessible(self, tmp_path: Path) -> None:
        config = create_test_config(approved_directory=str(tmp_path))
        assert config.approved_directory.is_dir()
        assert config.approved_directory.stat().st_mode & 0o444  # readable


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

@pytest.mark.sanity
class TestStorageSanity:
    @pytest.fixture
    async def db(self, tmp_path: Path):
        db_path = tmp_path / "sanity.db"
        manager = DatabaseManager(f"sqlite:///{db_path}")
        await manager.initialize()
        yield manager
        await manager.close()

    async def test_database_manager_initializes(self, db: DatabaseManager) -> None:
        assert await db.health_check()

    async def test_user_repo_creates_user(self, db: DatabaseManager) -> None:
        repo = UserRepository(db)
        user = UserModel(user_id=111, telegram_username="sanity_user")
        await repo.create_user(user)
        fetched = await repo.get_user(111)
        assert fetched is not None
        assert fetched.user_id == 111

    async def test_session_repo_creates_session(self, db: DatabaseManager) -> None:
        user_repo = UserRepository(db)
        session_repo = SessionRepository(db)

        user = UserModel(user_id=222, telegram_username="session_user")
        await user_repo.create_user(user)

        session = SessionModel(
            user_id=222,
            session_id="test-session-001",
            project_path="/tmp/test",
            created_at=datetime.now(UTC),
            last_used=datetime.now(UTC),
        )
        await session_repo.create_session(session)
        fetched = await session_repo.get_session("test-session-001")
        assert fetched is not None
        assert fetched.session_id == "test-session-001"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

@pytest.mark.sanity
class TestAuthSanity:
    async def test_auth_rejects_unknown_user(self) -> None:
        provider = WhitelistAuthProvider(allowed_users=[100, 200])
        assert await provider.authenticate(999, {}) is False

    async def test_auth_allows_known_user(self) -> None:
        provider = WhitelistAuthProvider(allowed_users=[100, 200])
        assert await provider.authenticate(100, {}) is True


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

@pytest.mark.sanity
class TestRateLimiterSanity:
    async def test_rate_limiter_allows_first_request(self, tmp_path: Path) -> None:
        config = create_test_config(
            approved_directory=str(tmp_path),
            rate_limit_requests=10,
            rate_limit_burst=20,
        )
        limiter = RateLimiter(config)
        allowed, msg = await limiter.check_rate_limit(user_id=1, cost=0.0, tokens=1)
        assert allowed is True
        assert msg is None


# ---------------------------------------------------------------------------
# Invite token auth (critical path — new user join flow)
# ---------------------------------------------------------------------------

@pytest.mark.sanity
class TestInviteTokenSanity:
    """Sanity checks for the invite token join flow."""

    @pytest.fixture
    async def db(self, tmp_path: Path):
        db_path = tmp_path / "invite.db"
        manager = DatabaseManager(f"sqlite:///{db_path}")
        await manager.initialize()
        yield manager
        await manager.close()

    async def test_invite_tokens_table_exists_after_migration(self, db: DatabaseManager) -> None:
        async with db.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='invite_tokens'"
            )
            row = await cursor.fetchone()
        assert row is not None, "invite_tokens table missing — migration 5 did not run"

    async def test_database_auth_allows_user_with_is_allowed_true(self, db: DatabaseManager) -> None:
        repo = UserRepository(db)
        await repo.create_user(UserModel(user_id=5000, telegram_username="invited", is_allowed=True))
        provider = DatabaseAuthProvider(db)
        assert await provider.authenticate(5000, {}) is True

    async def test_database_auth_rejects_user_with_is_allowed_false(self, db: DatabaseManager) -> None:
        repo = UserRepository(db)
        await repo.create_user(UserModel(user_id=5001, telegram_username="pending", is_allowed=False))
        provider = DatabaseAuthProvider(db)
        assert await provider.authenticate(5001, {}) is False

    async def test_invite_token_create_and_validate(self, db: DatabaseManager) -> None:
        admin_id = 1712495377
        user_repo = UserRepository(db)
        await user_repo.create_user(UserModel(user_id=admin_id, telegram_username="admin", is_allowed=True))

        invite_repo = InviteTokenRepository(db)
        token = InviteTokenModel(
            token="sanity_tok_abc123",
            created_by=admin_id,
            expires_at=datetime.now(UTC) + timedelta(hours=72),
            note="sanity test invite",
        )
        created = await invite_repo.create_token(token)
        assert created.token_id is not None

        fetched = await invite_repo.get_by_token("sanity_tok_abc123")
        assert fetched is not None
        assert fetched.is_valid()

    async def test_redeemed_invite_token_is_no_longer_valid(self, db: DatabaseManager) -> None:
        admin_id = 1712495377
        user_repo = UserRepository(db)
        await user_repo.create_user(UserModel(user_id=admin_id, telegram_username="admin", is_allowed=True))

        invite_repo = InviteTokenRepository(db)
        token = InviteTokenModel(
            token="sanity_tok_redeem",
            created_by=admin_id,
            expires_at=datetime.now(UTC) + timedelta(hours=72),
        )
        created = await invite_repo.create_token(token)
        await invite_repo.mark_used(created.token_id, used_by=99999)

        fetched = await invite_repo.get_by_token("sanity_tok_redeem")
        assert fetched is not None
        assert not fetched.is_valid()
