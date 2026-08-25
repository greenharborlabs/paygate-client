import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "setup-breez-cutover-env.sh"


def test_setup_breez_cutover_env_prefers_generic_and_preserves_legacy_entries(
    tmp_path: Path,
) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = config_dir / "config.yaml"
    config_path.write_text("payer:\n  backend: breez\n", encoding="utf-8")
    legacy = config_dir / "voltage-env.sh"
    legacy.write_text(
        "export PAYGATE_CLIENT_LND_REST_URL='https://example.test'\n"
        "export BREEZ_API_KEY='stale'\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            str(SCRIPT),
            "--use-process-env",
            "--skip-doctor",
            "--config",
            str(config_path),
        ],
        env={
            **os.environ,
            "BREEZ_API_KEY": "new-api-key",
            "BREEZ_MNEMONIC": "one two three four",
        },
        text=True,
        capture_output=True,
        check=True,
    )

    generic = config_dir / "paygate-env.sh"
    for path in (generic, legacy):
        text = path.read_text(encoding="utf-8")
        assert text.count("export BREEZ_API_KEY=") == 1
        assert text.count("export BREEZ_MNEMONIC=") == 1
        assert "new-api-key" in text
        assert "one two three four" in text
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "PAYGATE_CLIENT_LND_REST_URL" in legacy.read_text(encoding="utf-8")
    assert "new-api-key" not in result.stdout
    assert "one two three four" not in result.stdout
