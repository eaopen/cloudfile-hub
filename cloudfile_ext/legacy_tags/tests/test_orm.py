"""Run the real-model suite in a clean Django process, avoiding global settings."""
from pathlib import Path
import subprocess
import sys


def test_real_orm_and_view_in_separate_process():
    result = subprocess.run([sys.executable, str(Path(__file__).with_name('orm_check.py'))],
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
