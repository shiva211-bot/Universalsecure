---
name: GitHub after project transfer
description: Reconnecting a GitHub integration after moving a conversation into a Replit project.
---

When a conversation is moved into a project, resolve the GitHub integration again in the destination project instead of reusing the old handle. If the live status says `connect`, follow its note and attach it once. If the project still cannot provide a usable connection and the reconnect flow fails, stop and ask the user to connect GitHub from the project rather than retrying stale IDs or trying to bypass the integration.

**Why:** The transferred project reported a GitHub row as authorized, and `addIntegration` returned attached, but the connection was still unavailable to the project and the connection prompt rejected the stale references.

**How to apply:** Before any GitHub write after a conversation-to-project move, resolve the current integration row, read its current skill file, and confirm the project can use the connection. Do not assume that authorization in the originating conversation carries over.
