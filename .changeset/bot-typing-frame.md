---
'@alternatefutures/e2ee': patch
---

`ChatClient.typing(active)`: send the relay's ephemeral `typing` frame (the same encrypted + signed presence entry as `hello`, never stored) so a hosted member such as the swarm bridge can show "<agent> is typing" while it answers. Peers decay the signal after a few seconds; repeat `true` while busy and send `false` right before the message.
