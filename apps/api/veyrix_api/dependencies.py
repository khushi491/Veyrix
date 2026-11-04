"""Shared API access and database dependencies."""

from typing import Annotated

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from veyrix_api.config import settings
from veyrix_api.db import get_session

Db = Annotated[Session, Depends(get_session)]


def local_access() -> None:
    if not settings.veyrix_dev_mode:
        raise HTTPException(
            503, "Hosted authentication is not implemented; enable local development mode"
        )
