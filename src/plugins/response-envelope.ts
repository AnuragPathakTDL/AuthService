import fp from "fastify-plugin";
import type { FastifyReply } from "fastify";

const statusText: Record<number, string> = {
  200: "OK",
  201: "Created",
  202: "Accepted",
  204: "No Content",
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  409: "Conflict",
  412: "Precondition Failed",
  422: "Unprocessable Entity",
  429: "Too Many Requests",
  500: "Internal Server Error",
  503: "Service Unavailable",
};

type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

declare module "fastify" {
  interface FastifyReply {
    userMessage?: string;
    developerMessage?: string;
    setResponseMessages(userMessage?: string, developerMessage?: string): this;
  }
}

function defaultMessage(statusCode: number, isDeveloper: boolean): string {
  const text = statusText[statusCode];
  if (text) {
    return text;
  }
  if (isDeveloper) {
    return `HTTP ${statusCode}`;
  }
  return statusCode < 400 ? "Request completed" : "Request failed";
}

function parsePayload(payload: unknown): unknown {
  if (payload === undefined || payload === null) {
    return null;
  }

  if (Buffer.isBuffer(payload)) {
    const asString = payload.toString("utf8");
    try {
      return JSON.parse(asString) as JsonValue;
    } catch {
      return asString;
    }
  }

  if (typeof payload === "string") {
    try {
      return JSON.parse(payload) as JsonValue;
    } catch {
      return payload;
    }
  }

  if (typeof payload === "object") {
    return payload;
  }

  return payload;
}

function isEnvelope(payload: unknown): boolean {
  return (
    typeof payload === "object" &&
    payload !== null &&
    "success" in payload &&
    "statusCode" in payload
  );
}

function ensureObject(payload: unknown): Record<string, unknown> {
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    return payload as Record<string, unknown>;
  }
  return {};
}

function extractMessage(payload: unknown): string | undefined {
  if (payload && typeof payload === "object" && "message" in payload) {
    const value = (payload as { message?: unknown }).message;
    if (typeof value === "string" && value.trim().length > 0) {
      return value;
    }
  }

  if (typeof payload === "string" && payload.trim().length > 0) {
    return payload;
  }

  return undefined;
}

export default fp(async (fastify) => {
  fastify.decorateReply(
    "setResponseMessages",
    function setResponseMessages(
      this: FastifyReply,
      userMessage?: string,
      developerMessage?: string
    ) {
      if (userMessage !== undefined) {
        this.userMessage = userMessage;
      }
      if (developerMessage !== undefined) {
        this.developerMessage = developerMessage;
      }
      return this;
    }
  );

  fastify.addHook("onSend", async (request, reply, payload) => {
    // Skip wrapping for streams
    if (
      payload &&
      typeof payload === "object" &&
      "pipe" in (payload as object)
    ) {
      return payload;
    }

    const parsed = parsePayload(payload);

    if (isEnvelope(parsed)) {
      const envelopeObject =
        typeof parsed === "object" && parsed !== null ? parsed : {};

      return typeof payload === "string"
        ? payload
        : JSON.stringify(envelopeObject);
    }

    const statusCode = reply.statusCode === 204 ? 200 : reply.statusCode;
    if (reply.statusCode === 204) {
      reply.code(200);
    }

    const isError = statusCode >= 400;
    const userMessage = reply.userMessage ?? defaultMessage(statusCode, false);
    const derivedDeveloperMessage =
      reply.developerMessage ?? defaultMessage(statusCode, true);
    const payloadMessage = extractMessage(parsed);

    const envelope = isError
      ? {
          success: false,
          statusCode,
          userMessage:
            reply.userMessage ??
            payloadMessage ??
            defaultMessage(statusCode, false),
          developerMessage:
            reply.developerMessage ??
            payloadMessage ??
            defaultMessage(statusCode, true),
          data: {},
        }
      : {
          success: true,
          statusCode: 0,
          userMessage,
          developerMessage: derivedDeveloperMessage,
          data: ensureObject(parsed ?? {}),
        };

    reply.header("content-type", "application/json; charset=utf-8");
    return JSON.stringify(envelope);
  });
});
