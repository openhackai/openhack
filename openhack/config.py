import json
import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

CONFIG_DIR = Path.home() / ".openhack"
CONFIG_PATH = CONFIG_DIR / "config"

_PROVIDER_KEY_FIELDS = {
    "openhack": "openhack_api_key",
}


def _dotenv_nonempty_keys(path: Path) -> set[str]:
    """Return uppercase keys with non-empty values from a dotenv file."""
    keys: set[str] = set()
    if not path.exists():
        return keys
    try:
        for raw_line in path.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and val != "":
                keys.add(key.upper())
    except OSError:
        return set()
    return keys


def load_user_config() -> dict:
    """Load persistent config from ~/.openhack/config."""
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_user_config(data: dict) -> None:
    """Save persistent config to ~/.openhack/config."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass
    existing = load_user_config()
    existing.update(data)
    CONFIG_PATH.write_text(json.dumps(existing, indent=2) + "\n")
    # Config now holds long-lived bearer tokens; restrict to owner-only read/write.
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def resolve_provider(name: str) -> str:
    """Normalize provider name."""
    return name


PROD_APP_URL = "https://app.openhack.com"
PROD_BASE_URL = "https://api.openhack.com/v1"
DEV_APP_URL = "http://localhost:9080"
DEV_BASE_URL = "http://localhost:8787/v1"


class Settings(BaseSettings):
    """Minimal settings for the standalone scanner."""

    # Set OPENHACK_DEV=1 to point both URLs at local dev (Next.js app on :9080,
    # wrangler dev inference on :8787) instead of production.
    openhack_dev: bool = False

    llm_provider: str = "openhack"

    openhack_api_key: Optional[str] = None
    openhack_base_url: str = ""
    openhack_app_url: str = ""
    openhack_model_id: str = "kimi-k2.5"

    openhack_org_id: Optional[str] = None
    openhack_org_slug: Optional[str] = None
    openhack_org_name: Optional[str] = None
    openhack_user_email: Optional[str] = None
    openhack_user_first_name: Optional[str] = None
    openhack_user_last_name: Optional[str] = None
    openhack_read_timeout: int = 600
    openhack_connect_timeout: int = 30
    openhack_max_retries: int = 5

    # Send prompt_cache_key with API calls. Supported by OpenHack and OpenAI;
    # some OpenAI-compatible endpoints (e.g. Groq) reject unknown params.
    prompt_caching: bool = True

    recon_model_id: Optional[str] = None
    hunter_model_id: Optional[str] = None
    validator_model_id: Optional[str] = None
    browser_verifier_model_id: Optional[str] = None

    max_concurrent_hunters: int = 3
    max_concurrent_validators: int = 5

    compaction_threshold: float = 0.70
    tool_result_max_lines: int = 200
    checkpoint_enabled: bool = True

    # Scan scoping — exclude paths that are never production web attack surface
    scan_exclude_patterns: list[str] = [
        "**/test/**", "**/tests/**", "**/__tests__/**", "**/spec/**",
        "**/__mocks__/**", "**/fixtures/**", "**/__fixtures__/**",
        "**/e2e/**", "**/cypress/**", "**/playwright/**",
        "**/cli/**", "**/CLI/**",
        "**/docs/**", "**/documentation/**",
        "**/examples/**", "**/example/**", "**/samples/**", "**/demo/**", "**/demos/**",
        "**/tutorial/**", "**/tutorials/**", "**/playground/**", "**/sandbox/**",
        "**/mock/**", "**/mocks/**", "**/stub/**", "**/stubs/**",
        "**/scripts/**", "**/tools/**", "**/devtools/**",
        "**/benchmarks/**", "**/benchmark/**",
        "**/integration-tests/**",
        "**/*.test.*", "**/*.spec.*", "**/test_*",
        "**/conftest.py", "**/jest.config.*", "**/vitest.config.*",
        "**/.storybook/**", "**/stories/**",
    ]

    # Feature deep dive
    feature_hunt_enabled: bool = True
    max_feature_hunters: int = 7
    feature_hunter_max_iterations: int = 75
    max_concurrent_feature_hunters: int = 2
    feature_hunter_model_id: Optional[str] = None

    # Sandbox verification
    sandbox_enabled: bool = False
    sandbox_max_exploit_attempts: int = 7
    sandbox_health_check_timeout: int = 120
    sandbox_health_check_path: str = "/"
    sandbox_teardown_on_complete: bool = True

    # Browser verification
    # Browser verification
    browser_verification_enabled: bool = False
    browser_headless: bool = True
    browser_max_exploit_attempts: int = 7
    browser_timeout_ms: int = 30000

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    def model_post_init(self, __context) -> None:
        if not self.openhack_app_url:
            self.openhack_app_url = DEV_APP_URL if self.openhack_dev else PROD_APP_URL
        if not self.openhack_base_url:
            self.openhack_base_url = DEV_BASE_URL if self.openhack_dev else PROD_BASE_URL


def _build_settings() -> Settings:
    """Build Settings, overlaying ~/.openhack/config values as env-like overrides."""
    user_cfg = load_user_config()
    env_overrides = {}
    for key, val in user_cfg.items():
        if val is not None and val != "":
            env_overrides[key.upper()] = str(val)

    dotenv_keys = _dotenv_nonempty_keys(Path(".env"))
    old_env = {}
    for k, v in env_overrides.items():
        # Respect explicit non-empty environment variables, but allow persisted
        # config to fill missing or blank values. Also let .env values win.
        current = os.environ.get(k)
        if (current is None or current == "") and k not in dotenv_keys:
            old_env[k] = current
            os.environ[k] = v

    try:
        s = Settings()
    finally:
        for k, prev in old_env.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev
    return s


settings = _build_settings()


def reload_settings() -> None:
    """Reload settings from ~/.openhack/config and environment."""
    global settings
    settings = _build_settings()
