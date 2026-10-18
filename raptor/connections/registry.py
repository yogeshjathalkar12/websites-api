"""The connector contract and the list of connectors.

A connector is one small class. The router never knows provider details: it asks the registry for the connector, calls connect()
once when the user adds it and sync() whenever fresh data is wanted. A connector returns Signals; the router stores them
(deduplicated) in the `signals` table, which every other part of Raptor reads. To add a channel: write a Connector, register it,
and add its module to load_all()."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class ConnectorError(Exception):
    """Something the user can act on (wrong link, key not accepted, quota used up). The message is shown to them as is."""


@dataclass
class Field:
    """One input of a form, described so the apps can draw it without knowing the provider."""
    name: str
    label: str
    placeholder: str = ""
    help: str = ""
    secret: bool = False
    required: bool = True
    multiline: bool = False
    options: Optional[list] = None       # a list of {value, label}: drawn as a choice instead of a text box


@dataclass
class Action:
    """Something a person can do with a connection beyond reading it (send a test alert, send a text message)."""
    name: str
    label: str
    description: str = ""
    fields: list = field(default_factory=list)


@dataclass
class ConnectResult:
    external_id: str                     # the channel id / property id / place id: what makes this connection unique
    label: str                           # a friendly name to show
    config: dict = field(default_factory=dict)   # non-secret settings that sync() needs later
    secret: Optional[str] = None         # stored encrypted; None when the connector needs none
    provider: Optional[str] = None       # set when one sign-in creates connections of several kinds (Facebook Page, Lead Ads, Instagram)


@dataclass
class Signal:
    kind: str                            # 'metric' | 'mention' | 'lead' | 'event'
    name: str                            # 'subscribers', 'views', 'rating', 'new_comment'...
    value: Optional[float] = None
    text_value: Optional[str] = None
    entity: dict = field(default_factory=dict)
    occurred_at: Optional[datetime] = None
    dedupe_key: Optional[str] = None     # same key on the same connection = the same observation, stored once


class Context:
    """What the router gives a connector for an action: a way to count and record what it has done, without touching the database."""

    def __init__(self, count_today=None, record=None, org_id: str = "", recent=None):
        self._count_today, self._record, self.org_id, self._recent = count_today, record, org_id, recent

    def count_today(self, name: str) -> int:
        return self._count_today(name) if self._count_today else 0

    def record(self, signal: Signal) -> None:
        if self._record:
            self._record(signal)

    def recent(self, name: str, limit: int = 200) -> list:
        """The newest stored signals of this connection with that name, as dicts with `entity` and `occurred_at`."""
        return self._recent(name, limit) if self._recent else []


class Connector:
    provider: str = ""
    title: str = ""
    description: str = ""
    channel: str = ""                    # the tab it belongs to in the app: 'youtube', 'analytics', 'reviews', 'payments', 'alerts', ...
    category: str = "data"               # 'data' | 'channel' | 'alerts'
    auth: str = "none"                   # 'none' (a form), 'oauth' (the person signs in with the provider and approves access)
    can_reply: bool = False              # the connector can post a reply for the person (reply() is implemented)
    fields: list = []
    help: list = []                      # plain-words setup steps, shown beside the form
    actions: list = []                   # Actions a person can run on a connected connection
    settings: tuple = ()                 # keys of `config` the person may change later (a whitelist)
    inbound: bool = False                # receives data pushed to the server (webhooks) rather than fetching it
    unavailable_note: str = ""            # shown when the connector is not switched on (for example while Meta's approval is pending)
    extra: dict = {}                     # anything else the apps need to draw this connector (for example the list of alert events)
    syncable: bool = True                # has data to fetch; False for connectors that only send or only receive
    # Environment variables this connector needs ON THE SERVER (a shared key we pay for). Empty when the user brings everything.
    server_env: tuple = ()
    # Shared-key connectors cost us quota or money, so a connection may be synced at most this often (seconds).
    min_sync_interval: int = 900

    def available(self) -> bool:
        import os
        return all(os.environ.get(name) for name in self.server_env)

    def allowed_for(self, org_id: str) -> bool:
        """Whether this organization may use the connector. Always yes unless a connector limits itself to approved test accounts."""
        return True

    def redirect_uri(self) -> str:
        """Where the provider sends the person back after they sign in (Google by default)."""
        from . import google_oauth
        return google_oauth.redirect_uri()

    def connect(self, inputs: dict) -> ConnectResult:          # validates the user's input, may call the provider
        raise NotImplementedError

    def sync(self, connection: dict, secret: Optional[str]) -> list:   # -> list[Signal]
        return []

    def post_connect(self, connection: dict, secret: Optional[str]) -> None:   # after the connection is saved (e.g. register a webhook)
        return None

    def ingest_meta(self, connection: dict, secret: Optional[str], obj: str, entry: dict) -> tuple:
        """For Meta connectors: reads one entry of a webhook Meta sent for this connection's page or account. Returns (signals, config_patch)."""
        return [], {}

    def ingest(self, connection: dict, secret: Optional[str], body: bytes, headers: dict) -> tuple:
        """For inbound connectors: checks and reads what was pushed to the server. Returns (signals, config_patch)."""
        raise ConnectorError("This connection does not receive data.")

    def action(self, connection: dict, secret: Optional[str], name: str, params: dict, ctx: Context) -> dict:
        raise ConnectorError("This connection does not do that.")

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
            "channel": self.channel or self.provider, "auth": self.auth, "can_reply": self.can_reply, "inbound": self.inbound,
            "syncable": self.syncable, "help": list(self.help), "settings": list(self.settings),
            "available": self.available(), "unavailable_note": self.unavailable_note, "restricted": False, "min_sync_interval": self.min_sync_interval,
            "fields": [f.__dict__ for f in self.fields], "extra": self.extra,
            "actions": [{"name": a.name, "label": a.label, "description": a.description, "fields": [f.__dict__ for f in a.fields]} for a in self.actions],
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
    from . import ga4, reviews, rss, alerts, sms, webhooks, meta  # noqa: F401
    return REGISTRY
