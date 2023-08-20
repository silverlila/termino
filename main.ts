import { startServer } from "./server/server.ts";
import { startClient } from "./client/client.ts";

const args = Deno.args;

switch (args[0]) {
  case "server":
    startServer(8080);
    break;
  case "client":
    startClient();
    break;
  default:
    console.log("Usage:");
    console.log("deno run --allow-net index.ts server  // to start server");
    console.log("deno run --allow-net index.ts client  // to start client");
    break;
}
