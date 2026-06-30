"""Critical-path sanity tests. Fast, no external calls. Run before every deploy."""

import tempfile
from pathlib import Path

import pytest

from src.config import create_test_config
from src.security.auth import WhitelistAuthProvider
from src.security.rate_limiter import RateLimiter
from src.storage.database import DatabaseManager
from src.storage.models import SessionModel, UserModel
from src.storage.repositories import SessionRepository, UserRepository


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
        user = UserModel(user_id=111, username="sanity_user")
        await repo.create_user(user)
        fetched = await repo.get_user(111)
        assert fetched is not None
        assert fetched.user_id == 111

    async def test_session_repo_creates_session(self, db: DatabaseManager) -> None:
        user_repo = UserRepository(db)
        session_repo = SessionRepository(db)

        user = UserModel(user_id=222, username="session_user")
        await user_repo.create_user(user)

        session = SessionModel(
            user_id=222,
            session_id="test-session-001",
            project_path="/tmp/test",
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
