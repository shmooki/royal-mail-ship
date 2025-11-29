I am quite lazy to do flow charts so here is what we need for client and server...

Both:
Define a packet structure. Say... [author_id (16-num long), channel_id (8-num long), message_id (8-num long), payload (variable)].
Default layout will be a chat bar like Discord's. We add commands to allow for more stuff and changing layout (i.e. /settings will let you access the settings menu, /login to login...)

Server:
Hashing for usernames and passwords.
Encryption/decryption of messages.
Authenticating users (literally just compare hashes...)
Reject unauthenticated interactions.

Client:
Sending/receiving broadcasts (client sends message => server broadcasts the message to all other active participants in the chat).
Different menus to list out your friends, channels...