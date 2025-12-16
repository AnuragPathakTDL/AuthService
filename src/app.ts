import Fastify from "fastify";
import sensible from "@fastify/sensible";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import { loadConfig } from "./config";
import prismaPlugin from "./plugins/prisma";
import jwtPlugin from "./plugins/jwt";
import userServicePlugin from "./plugins/user-service";
import publicAuthRoutes from "./routes/public-auth";
import { buildJwks } from "./utils/jwks";

export async function buildApp() {
  const config = loadConfig();
  const fastify = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      transport:
        config.NODE_ENV === "development"
          ? {
              target: "pino-pretty",
              options: {
                colorize: true,
                translateTime: "SYS:standard",
              },
            }
          : undefined,
    },
    trustProxy: true,
    bodyLimit: config.HTTP_BODY_LIMIT,
  });

  await fastify.register(sensible);
  await fastify.register(cors, { origin: false });
  await fastify.register(helmet, {
    contentSecurityPolicy: false,
  });
  await fastify.register(prismaPlugin);
  await fastify.register(jwtPlugin);
  await fastify.register(userServicePlugin);
  await fastify.register(publicAuthRoutes);

  fastify.get("/health", async () => ({ status: "ok" }));

  fastify.get("/.well-known/jwks.json", async () => {
    return buildJwks({
      publicKey: config.AUTH_JWT_PUBLIC_KEY,
      keyId: config.AUTH_JWT_KEY_ID,
    });
  });

  return fastify;
}
