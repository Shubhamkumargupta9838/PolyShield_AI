import os
import sys
from pathlib import Path
import pytest

root_dir = str(Path(__file__).parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from backend.app.workers.celery_app import celery_app

os.environ["CELERY_TASK_ALWAYS_EAGER"] = "True"
celery_app.conf.task_always_eager = True


@pytest.fixture(autouse=True)
def force_celery_eager_mode():
    original = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    yield
    celery_app.conf.task_always_eager = original
