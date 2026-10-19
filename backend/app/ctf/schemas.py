import re
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_serializer,
    field_validator,
)


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


def validate_resource_url(value: str | None) -> str | None:
    if value is None:
        return None

    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise ValueError("Invalid characters in resource URL")

    value = value.strip()

    if not value:
        return None

    if not value.startswith("/") or value.startswith("//"):
        raise ValueError("Resource URL must be a local absolute path")

    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("Invalid percent encoding in resource URL")

    parsed = urlsplit(value)

    if parsed.scheme or parsed.netloc:
        raise ValueError("External resource URLs are not allowed")

    path = parsed.path

    while True:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Resource URL must be a local absolute path")

        if "\\" in path or any(
            ord(char) < 32 or 127 <= ord(char) <= 159 for char in path
        ):
            raise ValueError("Invalid characters in resource URL")

        if any(part in (".", "..") for part in path.split("/")):
            raise ValueError("Resource URL cannot contain traversal segments")

        decoded = unquote(path, errors="strict")

        if decoded == path:
            return value

        if "?" in decoded or "#" in decoded:
            raise ValueError("Encoded query or fragment delimiter in resource path")

        path = decoded


class FlagInput(Input):
    flag: SecretStr = Field(max_length=256)


class ChallengeCreate(Input):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{1,31}$")
    title: str = Field(min_length=1, max_length=150)
    description: str = Field(min_length=1, max_length=20000)
    category: str = Field(min_length=1, max_length=50)
    difficulty: Literal["easy", "medium", "hard"] = "easy"
    resource_url: str | None = Field(default=None, max_length=2048)
    points: int = Field(gt=0, le=10000, strict=True)
    flag: SecretStr = Field(min_length=6, max_length=256)
    is_published: bool = False

    @field_validator("resource_url")
    @classmethod
    def check_resource_url(cls, value: str | None) -> str | None:
        return validate_resource_url(value)


class ChallengeUpdate(Input):
    expected_revision: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1, max_length=150)
    description: str | None = Field(default=None, min_length=1, max_length=20000)
    category: str | None = Field(default=None, min_length=1, max_length=50)
    difficulty: Literal["easy", "medium", "hard"] | None = None
    resource_url: str | None = Field(default=None, max_length=2048)
    points: int | None = Field(default=None, gt=0, le=10000, strict=True)
    flag: SecretStr | None = Field(default=None, min_length=6, max_length=256)
    is_published: bool | None = None

    @field_validator("resource_url")
    @classmethod
    def check_resource_url(cls, value: str | None) -> str | None:
        return validate_resource_url(value)


class ResetInput(Input):
    confirmation: Literal["RESET DEMO RESULTS"]
    expected_generation: int = Field(ge=0)


class ChallengeOutput(BaseModel):
    id: int
    code: str | None
    title: str
    description: str
    category: str
    difficulty: Literal["easy", "medium", "hard"]
    resource_url: str | None
    points: int
    is_published: bool
    revision: int
    solved: bool


class UTCOutput(BaseModel):
    @field_serializer("submitted_at", "last_solve_at", check_fields=False)
    def utc_time(self, value):
        return (
            value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
            if value
            else None
        )


class AttemptOutput(UTCOutput):
    id: int
    user_id: int
    username: str
    challenge_id: int
    code: str | None
    title: str
    result: str
    is_correct: bool
    submitted_at: datetime


class LeaderOutput(UTCOutput):
    rank: int
    user_id: int
    username: str
    points: int
    last_solve_at: datetime | None
