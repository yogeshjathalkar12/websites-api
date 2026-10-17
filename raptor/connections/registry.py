"""The connector contract and the list of connectors.

A connector is one small class. The router never knows provider details: it asks the registry for the connector, calls connect()
once when the user adds it and sync() whenever fresh data is wanted. A connector returns Signals; the router stores them
(deduplicated) in the `signals` table, which every other part of Raptor reads. To add a channel: write a Connector, register it."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class ConnectorError(Exception):
    """Something the user can act on (wrong link, key not accepted, quota used up). The message is shown to them as is."""


@dataclass
class Field:
    """One input of the "connect" form, described so the web app can draw it without knowing the provider."""
    name: str
    label: str
    placeholder: str = ""
    help: str = ""
    secret: bool = False
    required: bool = True


@dataclass
class ConnectResult:
    external_id: str                     # the channel id / property id / place id: what makes this connection unique
    label: str                           # a friendly name to show
    config: dict = field(default_factory=dict)   # non-secret settings that sync() needs later
    secret: Optional[str] = None         # stored encrypted; None when the connector needs none


@dataclass
class Signal:
    kind: str                            # 'metric' | 'mention' | 'lead' | 'event'
    name: str                            # 'subscribers', 'views', 'rating', 'new_comment'...
    value: Optional[float] = None
    text_value: Optional[str] = None
    entity: dict = field(default_factory=dict)
    occurred_at: Optional[datetime] = None
    dedupe_key: Optional[str] = None     # same key on the same connection = the same observation, stored once


class Connector:
    provider: str = ""
    title: str = ""
    description: str = ""
    category: str = "data"               # 'data' | 'channel' | 'alerts'
    auth: str = "none"                   # 'none' (a form), 'oauth' (the person signs in with the provider and approves access)
    can_reply: bool = False              # the connector can post a reply for the person (reply() is implemented)
    fields: list = []
    # Environment variables this connector needs ON THE SERVER (a shared key we pay for). Empty when the user brings everything.
    server_env: tuple = ()
    # Shared-key connectors cost us quota or money, so a connection may be synced at most this often (seconds).
    min_sync_interval: int = 900

    def available(self) -> bool:
        import os
        return all(os.environ.get(name) for name in self.server_env)

    def connect(self, inputs: dict) -> ConnectResult:          # validates the user's input, may call the provider
        raise NotImplementedError

    def sync(self, connection: dict, secret: Optional[str]) -> list:   # -> list[Signal]
        raise NotImplementedError

    # --- sign-in connectors (auth == 'oauth') ---
    def authorize_url(self, state: str, redirect_uri: str) -> str:
        raise NotImplementedError

    def complete(self, code: str, redirect_uri: str) -> ConnectResult:   # after the person approved: code -> a stored connection
        raise NotImplementedError

    def revoke(self, secret: Optional[str]) -> None:                  # best effort, when the connection is removed
        return None

    def reply(self, connection: dict, secret: Optional[str], parent_id: str, text: str) -> str:   # -> id of the posted reply
        raise ConnectorError("This connection cannot post replies.")

    def describe(self) -> dict:
        return {
            "provider": self.provider, "title": self.title, "description": self.description, "category": self.category,
            "auth": self.auth, "can_reply": self.can_reply,
            "available": self.available(), "min_sync_interval": self.min_sync_interval,
            "fields": [f.__dict__ for f in self.fields],
        }


REGISTRY: dict = {}


def register(connector: Connector) -> Connector:
    REGISTRY[connector.provider] = connector
    return connector


def get(provider: str) -> Optional[Connector]:
    return REGISTRY.get(provider)


def load_all() -> dict:
    """Imports every connector module (each registers itself). Kept in one place so adding a channel is one line here."""
    from . import youtube, youtube_account  # noqa: F401
    return REGISTRY
