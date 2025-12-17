import fp from "fastify-plugin";
import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { Prisma, UserRole } from "@prisma/client";
import {
  registerUser,
  loginUser,
  issueTokensForUser,
  rotateRefreshToken,
  revokeSessions,
  AuthError,
} from "../services/auth";
import {
  registerBodySchema,
  registerResponseSchema,
  loginBodySchema,
  tokenResponseSchema,
  updateLanguageBodySchema,
  refreshBodySchema,
  logoutBodySchema,
  oauthPasswordBodySchema,
} from "../schemas/auth";
import { loadConfig } from "../config";

const config = loadConfig();

export default fp(async function publicAuthRoutes(fastify: FastifyInstance) {
  fastify.post("/v1/auth/register", {
    schema: {
      body: registerBodySchema,
      response: {
        201: registerResponseSchema,
      },
    },
    handler: async (request, reply) => {
      const body = registerBodySchema.parse(request.body);
      const isAdminRegistration = body.role === "ADMIN";
      const adminCountBefore = isAdminRegistration
        ? await request.server.prisma.user.count({
            where: { role: UserRole.ADMIN },
          })
        : 0;
      if (body.role === "ADMIN") {
        if (!config.SERVICE_AUTH_TOKEN) {
          throw fastify.httpErrors.forbidden("Admin registration disabled");
        }
        const headerValue = request.headers["x-service-token"];
        const headerToken = Array.isArray(headerValue)
          ? headerValue[0]
          : headerValue;
        if (headerToken !== config.SERVICE_AUTH_TOKEN) {
          throw fastify.httpErrors.forbidden("Invalid service token");
        }
      }
      try {
        const result = await registerUser({
          prisma: request.server.prisma,
          email: body.email,
          username: body.username,
          password: body.password,
          role: body.role,
          preferredLanguageId:
            body.preferredLanguageId ?? config.DEFAULT_LANGUAGE_ID,
          deviceId: body.deviceId,
          signAccessToken: request.server.signAccessToken,
        });

        if (
          result.user.role === UserRole.ADMIN &&
          request.server.userService.isEnabled
        ) {
          const isFirstAdmin = adminCountBefore === 0;
          try {
            const roles = await request.server.userService.listRoles();
            const targetRoleName = isFirstAdmin ? "SUPER_ADMIN" : "ADMIN";
            const targetRole = roles.find(
              (role) => role.name.toUpperCase() === targetRoleName
            );
            if (targetRole) {
              await request.server.userService.assignRole({
                userId: result.user.id,
                roleId: targetRole.id,
                grantedBy: isFirstAdmin ? result.user.id : undefined,
              });
            } else {
              request.log.warn(
                { targetRoleName },
                "Target admin role not found in UserService; user registered without RBAC assignments"
              );
            }
          } catch (serviceError) {
            request.log.error(
              { err: serviceError },
              "Failed to assign admin role via UserService"
            );
          }
        }

        return reply.code(201).send({
          user: {
            id: result.user.id,
            email: result.user.email,
            username: result.user.username,
            role: result.user.role,
            preferredLanguageId: result.user.preferredLanguageId,
            createdAt: result.user.createdAt.toISOString(),
            updatedAt: result.user.updatedAt.toISOString(),
          },
          tokens: result.tokens,
        });
      } catch (error) {
        if (error instanceof Prisma.PrismaClientKnownRequestError) {
          if (error.code === "P2002") {
            throw fastify.httpErrors.conflict(
              "Email or username already exists"
            );
          }
        }
        request.log.error({ err: error }, "Failed to register user");
        throw fastify.httpErrors.internalServerError();
      }
    },
  });

  fastify.post("/v1/auth/login", {
    schema: {
      body: loginBodySchema,
      response: {
        200: tokenResponseSchema,
      },
    },
    handler: async (request) => {
      const body = loginBodySchema.parse(request.body);
      try {
        const { tokens, user } = await loginUser({
          prisma: request.server.prisma,
          identifier: { email: body.email, username: body.username },
          password: body.password,
          deviceId: body.deviceId,
          signAccessToken: request.server.signAccessToken,
        });

        if (
          user.role === UserRole.ADMIN &&
          request.server.userService.isEnabled
        ) {
          const context = await request.server.userService
            .getUserContext(user.id)
            .catch((serviceError) => {
              request.log.error(
                { err: serviceError, userId: user.id },
                "Failed to validate admin RBAC assignments"
              );
              throw fastify.httpErrors.internalServerError();
            });
          const hasActiveRole = context.assignments.some(
            (assignment) => assignment.active
          );
          if (!hasActiveRole) {
            throw fastify.httpErrors.forbidden(
              "Admin access requires active role assignments"
            );
          }
        }

        return tokens;
      } catch (error) {
        if (error instanceof Error && error.message === "Invalid credentials") {
          throw fastify.httpErrors.unauthorized("Invalid credentials");
        }
        request.log.error({ err: error }, "Failed to login user");
        throw fastify.httpErrors.internalServerError();
      }
    },
  });

  fastify.post("/v1/auth/oauth/token", {
    schema: {
      consumes: ["application/x-www-form-urlencoded", "application/json"],
      body: oauthPasswordBodySchema,
      response: {
        200: tokenResponseSchema,
      },
    },
    handler: async (request) => {
      const body = oauthPasswordBodySchema.parse(request.body);

      if (body.grant_type !== "password") {
        throw fastify.httpErrors.badRequest("Unsupported grant_type");
      }

      const identifierValue = body.username;
      const identifier = identifierValue.includes("@")
        ? { email: identifierValue }
        : { username: identifierValue };

      try {
        const { tokens, user } = await loginUser({
          prisma: request.server.prisma,
          identifier,
          password: body.password,
          deviceId: body.device_id,
          signAccessToken: request.server.signAccessToken,
        });

        if (
          body.scope &&
          body.scope
            .split(/\s+/)
            .filter(Boolean)
            .some((scope) => scope.toLowerCase() === "admin") &&
          user.role !== UserRole.ADMIN
        ) {
          throw fastify.httpErrors.forbidden(
            "Admin scope requires administrative account"
          );
        }

        return tokens;
      } catch (error) {
        if (error instanceof Error && error.message === "Invalid credentials") {
          throw fastify.httpErrors.unauthorized("Invalid credentials");
        }
        request.log.error({ err: error }, "Failed to exchange password grant");
        throw fastify.httpErrors.internalServerError();
      }
    },
  });

  fastify.post("/v1/auth/token/refresh", {
    schema: {
      body: refreshBodySchema,
      response: {
        200: tokenResponseSchema,
      },
    },
    handler: async (request) => {
      const body = refreshBodySchema.parse(request.body);
      try {
        return await rotateRefreshToken({
          prisma: request.server.prisma,
          refreshToken: body.refreshToken,
          deviceId: body.deviceId,
          signAccessToken: request.server.signAccessToken,
        });
      } catch (error) {
        if (error instanceof AuthError) {
          if (error.code === "EXPIRED_REFRESH_TOKEN") {
            throw fastify.httpErrors.unauthorized("Refresh token expired");
          }
          throw fastify.httpErrors.unauthorized("Invalid refresh token");
        }
        request.log.error({ err: error }, "Failed to refresh tokens");
        throw fastify.httpErrors.internalServerError();
      }
    },
  });

  fastify.post("/v1/auth/logout", {
    schema: {
      body: logoutBodySchema,
      response: {
        204: z.null(),
      },
    },
    handler: async (request, reply) => {
      const body = logoutBodySchema.parse(request.body);
      const authHeader = request.headers.authorization;
      if (!authHeader) {
        throw fastify.httpErrors.unauthorized("Missing access token");
      }

      const token = authHeader.replace(/^Bearer\s+/i, "");
      let payload: { sub?: string };
      try {
        payload = await request.server.jwt.verify(token);
      } catch (error) {
        request.log.warn(
          { err: error },
          "Failed to verify token during logout"
        );
        throw fastify.httpErrors.unauthorized("Invalid access token");
      }

      const userId = payload.sub;
      if (!userId) {
        throw fastify.httpErrors.unauthorized("Invalid subject");
      }

      await revokeSessions({
        prisma: request.server.prisma,
        userId,
        refreshToken: body.refreshToken,
        deviceId: body.deviceId,
        allDevices: body.allDevices,
      });

      return reply.status(204).send();
    },
  });

  fastify.patch("/v1/auth/language", {
    schema: {
      body: updateLanguageBodySchema,
      response: {
        200: tokenResponseSchema,
      },
    },
    handler: async (request) => {
      const token = request.headers.authorization?.replace(/^Bearer\s+/i, "");
      if (!token) {
        throw fastify.httpErrors.unauthorized("Missing access token");
      }

      const body = updateLanguageBodySchema.parse(request.body);

      let payload: { sub?: string };
      try {
        payload = await request.server.jwt.verify(token);
      } catch (error) {
        request.log.warn(
          { err: error },
          "Failed to verify token for language update"
        );
        throw fastify.httpErrors.unauthorized("Invalid token");
      }

      const userId = payload.sub;
      if (!userId) {
        throw fastify.httpErrors.unauthorized("Invalid subject");
      }

      const user = await request.server.prisma.user.update({
        where: { id: userId },
        data: { preferredLanguageId: body.preferredLanguageId },
      });

      return issueTokensForUser({
        prisma: request.server.prisma,
        user: {
          id: user.id,
          role: user.role,
          username: user.username,
          preferredLanguageId: user.preferredLanguageId,
        },
        signAccessToken: request.server.signAccessToken,
      });
    },
  });
});
