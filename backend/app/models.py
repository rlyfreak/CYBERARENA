from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        index=True,
        nullable=False,
    )
    password_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
    )
    submissions: Mapped[list["Submission"]] = relationship(back_populates="user")
    is_admin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("0")
    )
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("0")
    )


class Challenge(Base):
    __tablename__ = "challenges"

    __table_args__ = (
        CheckConstraint(
            "points > 0",
            name="ck_challenges_points_positive",
        ),
        CheckConstraint(
            "difficulty IN ('easy', 'medium', 'hard')",
            name="ck_challenges_difficulty",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str | None] = mapped_column(String(32), unique=True)
    is_published: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("0")
    )
    revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    difficulty: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="easy",
        server_default=text("'easy'"),
    )
    resource_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    title: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    category: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    points: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    flag_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    submissions: Mapped[list["Submission"]] = relationship(back_populates="challenge")


class Submission(Base):
    __tablename__ = "submissions"

    id: Mapped[int] = mapped_column(primary_key=True)
    result: Mapped[str] = mapped_column(
        String(32), nullable=False, default="incorrect", server_default="incorrect"
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
        index=True,
    )

    challenge_id: Mapped[int] = mapped_column(
        ForeignKey("challenges.id"),
        nullable=False,
        index=True,
    )

    is_correct: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    submitted_at: Mapped[datetime] = mapped_column(
        DateTime,
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="submissions")

    challenge: Mapped["Challenge"] = relationship(back_populates="submissions")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, nullable=False)
    window_started: Mapped[int] = mapped_column(Integer, nullable=False)
    blocked_until: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    expires_at: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )


class Solve(Base):
    __tablename__ = "solves"
    __table_args__ = (
        UniqueConstraint("user_id", "challenge_id", name="uq_solve_user_challenge"),
        CheckConstraint("points_awarded > 0", name="ck_solve_points_positive"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    challenge_id: Mapped[int] = mapped_column(ForeignKey("challenges.id"), index=True)
    submission_id: Mapped[int] = mapped_column(ForeignKey("submissions.id"), unique=True)
    points_awarded: Mapped[int] = mapped_column(Integer)
    solved_at: Mapped[datetime] = mapped_column(DateTime)


class CtfRateLimit(Base):
    __tablename__ = "ctf_rate_limits"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    window_started: Mapped[int] = mapped_column(Integer)
    attempts: Mapped[int] = mapped_column(Integer)


class CtfVerificationLease(Base):
    """Global verification capacity shared by processes, not an in-memory mutex."""

    __tablename__ = "ctf_verification_leases"
    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[int] = mapped_column(Integer, index=True)


class CtfState(Base):
    __tablename__ = "ctf_state"
    id: Mapped[int] = mapped_column(primary_key=True)
    generation: Mapped[int] = mapped_column(Integer, default=0)


class SchemaMigration(Base):
    __tablename__ = "schema_migrations"
    name: Mapped[str] = mapped_column(String(100), primary_key=True)
