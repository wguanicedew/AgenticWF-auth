"""The provider's admin API as authsvc needs it: groups, their members, users.

A provider package implements ``Directory`` on its admin API (Keycloak's Admin REST API, Logto's
Management API) in neutral terms: a group has members, some of whom are its admins.
"""

from __future__ import annotations

from typing import Protocol


class ManagementError(Exception):
    """The admin API refused (``status``: the HTTP status authsvc answers with, e.g. 404, 409)."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class ManagementUnavailableError(Exception):
    """The admin API could not be reached."""


class Directory(Protocol):
    """Group dicts: {id, name, description}. User dicts: {id, username, name, email, enabled}.
    Unknown ids raise ManagementError(404); name clashes ManagementError(409)."""

    def groups(self) -> list[dict]: ...
    def group(self, group_id: str) -> dict: ...
    def create_group(self, name: str, description: str) -> dict: ...
    def update_group(self, group_id: str, fields: dict) -> dict: ...
    def delete_group(self, group_id: str) -> None: ...

    def group_members(self, group_id: str) -> list[dict]:
        """Users, each with `admin` (bool)."""
        ...

    def add_member(self, group_id: str, user_id: str, admin: bool = False) -> None: ...
    def remove_member(self, group_id: str, user_id: str) -> None: ...
    def set_admin(self, group_id: str, user_id: str, admin: bool) -> None: ...

    def user_groups(self, user_id: str) -> list[dict]:
        """The user's groups: [{id, name, admin}]."""
        ...

    def user(self, user_id: str) -> dict: ...
    def find_user(self, email: str) -> dict | None: ...
