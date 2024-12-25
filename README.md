---
title: "Termino: Chat CLI App"
description: "A stateless chat application built with Deno."
---

# Termino

**Termino** is a simple stateless chat application built with Deno. The application allows users to create chat channels, join existing channels, and communicate in real-time using WebSockets.

## Features

- **Channel Creation**: Users can create their own chat channels by specifying a unique channel ID and password.
- **Join Existing Channel**: Users can join existing channels by providing the correct channel ID and password.
- **Real-time Communication**: Messages sent within a channel are broadcasted in real-time to all channel members.
- **Rate Limiting**: Users are limited in the frequency with which they can send messages to prevent spam.
- **System Notifications**: System notifications are sent to the channel when a user joins or leaves.
- **Command-based Interface**: The application is controlled via intuitive commands such as `/create`, `/join`, and `/leave`.

## Architecture

The application is split into client and server modules:

- **Client**:
  - Connects to the server through a WebSocket endpoint.
  - Listens for user input, sends commands/messages to the server, and handles server responses.
  - Provides user feedback through the console.
- **Server**:
  - Handles incoming WebSocket connections.
  - Processes client commands and broadcasts messages.
  - Maintains a channel manager that keeps track of active channels and the clients connected to them.
  - Uses simple rate limiting to prevent frequent message sending by a single user.

## Installation and Setup

1. Clone the repository.
   ```bash
   git clone [YOUR_REPOSITORY_LINK]
   ```
2. To start the server or client, use the main.ts file:

   ```bash
   Start the server
   deno run --allow-net main.ts server

   Start the client
   deno run --allow-net main.ts client

   ```

## Usage

1. **Create a Channel**:
   ```bash
   /create
   ```
2. **Join an Existing Channel**:
   ```bash
   /join
   ```
3. **Leave the Current Channel**:
   ```bash
   /leave
   ```
4. **View Help Commands**:
   ```bash
   /help
   ```
5. **Exit the App**:
   ```bash
   /exit
   ```


