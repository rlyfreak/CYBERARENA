from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_serializer


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class FlagInput(Input):
    flag: SecretStr = Field(max_length=256)


class ChallengeCreate(Input):
    code: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{1,31}$")
    title: str = Field(min_length=1, max_length=150)
    description: str = Field(min_length=1, max_length=20000)
    category: str = Field(min_length=1, max_length=50)
    points: int = Field(gt=0, le=10000, strict=True)
    flag: SecretStr = Field(min_length=6, max_length=256)
    is_published: bool = False


class ChallengeUpdate(Input):
    expected_revision: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1, max_length=150)
    description: str | None = Field(default=None, min_length=1, max_length=20000)
    category: str | None = Field(default=None, min_length=1, max_length=50)
    points: int | None = Field(default=None, gt=0, le=10000, strict=True)
    flag: SecretStr | None = Field(default=None, min_length=6, max_length=256)
    is_published: bool | None = None


class ResetInput(Input):
    confirmation: Literal["RESET DEMO RESULTS"]
    expected_generation: int = Field(ge=0)


class ChallengeOutput(BaseModel):
    id: int
    code: str | None
    title: str
    description: str
    category: str
    points: int
    is_published: bool
    revision: int
    solved: bool


class UTCOutput(BaseModel):
    @field_serializer("submitted_at", "last_solve_at", check_fields=False)
    def utc_time(self, value):
        return value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if value else None


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
