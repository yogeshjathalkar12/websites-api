"""Connections: outside channels and data sources an organization links to Raptor (YouTube, Google Analytics, review ratings,
webhooks, payments, alerts...). One small module per provider, all registered in registry.py; router.py is the only HTTP surface.
Every connection belongs to an ORGANIZATION (owner_id = org id), never to a hard-coded account."""
