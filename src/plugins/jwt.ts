import fp from "fastify-plugin";
import fastifyJwt from "@fastify/jwt";
import type { FastifyInstance, FastifyPluginAsync } from "fastify";
import type { FastifyJWTOptions } from "@fastify/jwt";
import { loadConfig } from "../config";

declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: {
      sub: string;
      role: "ADMIN" | "CUSTOMER";
      username: string;
      languageId: string;
    };
    user: {
      userId: string;
      role: "ADMIN" | "CUSTOMER";
      username: string;
      languageId: string;
    };
  }
}

async function jwtPlugin(fastify: FastifyInstance) {
  const config = loadConfig();

  const jwtPluginInstance = fastifyJwt as FastifyPluginAsync<FastifyJWTOptions>;

  await fastify.register(jwtPluginInstance, {
    secret: {
      private: config.AUTH_JWT_PRIVATE_KEY,
      public: config.AUTH_JWT_PUBLIC_KEY,
    },
    sign: {
      algorithm: "RS256",
      kid: config.AUTH_JWT_KEY_ID,
      iss: "auth-service",
      aud: "pocketlol-services",
    },
    verify: {
      algorithms: ["RS256"],
      allowedAud: "pocketlol-services",
      allowedIss: "auth-service",
    },
  });

  fastify.decorate(
    "signAccessToken",
    async (payload: {
      sub: string;
      role: "ADMIN" | "CUSTOMER";
      username: string;
      languageId: string;
      expiresIn: number;
    }) => {
      const { sub, role, username, languageId, expiresIn } = payload;
      return fastify.jwt.sign(
        { sub, role, username, languageId },
        { expiresIn }
      );
    }
  );
}

declare module "fastify" {
  interface FastifyInstance {
    signAccessToken(payload: {
      sub: string;
      role: "ADMIN" | "CUSTOMER";
      username: string;
      languageId: string;
      expiresIn: number;
    }): Promise<string>;
  }
}

export default fp(jwtPlugin, {
  name: "jwt",
  dependencies: ["prisma"],
});
