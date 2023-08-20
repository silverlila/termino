import { Application, Router } from "https://deno.land/x/oak@v12.6.0/mod.ts";
import { handler } from "./router.ts";

export async function startServer(port: number) {
  const app = new Application();

  const router = new Router();
  router.get("/start", handler);

  app.use(router.routes());
  app.use(router.allowedMethods());

  console.log(`Listening at http://localhost:${port}`);
  return await app.listen({ port });
}
