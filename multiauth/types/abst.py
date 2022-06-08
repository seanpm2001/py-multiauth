"""Abstract representation."""

# pylint: disable=missing-docstring, too-few-public-methods

from typing import Any

from multiauth.types.http import HTTPMethod
from multiauth.types.main import Token


class MultiAuthBase:

    _headers: dict[str, dict]
    _schemas: dict

    @property
    def users(self) -> dict:
        raise NotImplementedError()

    @property
    def headers(self) -> dict[str, dict]:
        raise NotImplementedError()

    def sign(
        self,
        url: str,
        username: str,
        method: HTTPMethod,
        headers: dict[str, str],
        formatted_payload: Any,
    ) -> dict[str, str]:

        raise NotImplementedError

    def reauthenticate(
        self,
        username: str,
        headers: dict[str, str] | None = None,
        no_auth: bool = False,
    ) -> tuple[dict[str, str], str | None]:

        raise NotImplementedError

    def authenticate(
        self,
        username: str,
    ) -> tuple[dict[str, str], str]:

        raise NotImplementedError

    def authenticate_users(self) -> dict[str, Token | None]:

        raise NotImplementedError
