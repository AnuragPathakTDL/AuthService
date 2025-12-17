import { Prisma, PrismaClient, UserRole } from "@prisma/client";
import { randomBytes, createHash } from "node:crypto";
import { loadConfig } from "../config";
import type { TokenResponse } from "../schemas/auth";
import { hashPassword, verifyPassword } from "../utils/password";

const config = loadConfig();

export class AuthError extends Error {
  constructor(
    message: string,
    public readonly code:
      | "INVALID_REFRESH_TOKEN"
      | "EXPIRED_REFRESH_TOKEN"
      | "USER_DISABLED"
  ) {
    super(message);
    this.name = "AuthError";
  }
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function createRefreshToken(): string {
  return randomBytes(48).toString("base64url");
}

async function persistSession(params: {
  prisma: PrismaClient;
  userId: string;
  refreshToken: string;
  deviceId?: string;
}): Promise<TokenResponse> {
  const { prisma, userId, refreshToken, deviceId } = params;

  const refreshExpiresAt = new Date(
    Date.now() + config.REFRESH_TOKEN_TTL * 1000
  );
  const hashedToken = hashToken(refreshToken);

  if (config.REFRESH_TOKEN_ROTATION) {
    await prisma.session.deleteMany({
      where: {
        userId,
        ...(deviceId ? { deviceId } : {}),
      },
    });
  }

  await prisma.session.create({
    data: {
      userId,
      refreshTokenHash: hashedToken,
      expiresAt: refreshExpiresAt,
      deviceId,
    },
  });

  return {
    accessToken: "",
    refreshToken,
    expiresIn: config.ACCESS_TOKEN_TTL,
    refreshExpiresIn: config.REFRESH_TOKEN_TTL,
    tokenType: "Bearer",
  };
}

export async function registerUser(params: {
  prisma: PrismaClient;
  email: string;
  username: string;
  password: string;
  role?: UserRole;
  preferredLanguageId?: string;
  deviceId?: string;
  signAccessToken: (payload: {
    sub: string;
    role: UserRole;
    username: string;
    languageId: string;
    expiresIn: number;
  }) => Promise<string>;
}): Promise<{
  user: {
    id: string;
    email: string;
    username: string;
    role: UserRole;
    preferredLanguageId: string;
    createdAt: Date;
    updatedAt: Date;
  };
  tokens: TokenResponse;
}> {
  const {
    prisma,
    email,
    username,
    password,
    role = UserRole.CUSTOMER,
    preferredLanguageId,
    deviceId,
    signAccessToken,
  } = params;

  const passwordHash = await hashPassword(password);

  const user = await prisma.user.create({
    data: {
      email,
      username,
      passwordHash,
      role,
      preferredLanguageId: preferredLanguageId ?? config.DEFAULT_LANGUAGE_ID,
    },
  });

  const refreshToken = createRefreshToken();
  const tokens = await persistSession({
    prisma,
    userId: user.id,
    refreshToken,
    deviceId,
  });

  tokens.accessToken = await signAccessToken({
    sub: user.id,
    role: user.role,
    username: user.username,
    languageId: user.preferredLanguageId,
    expiresIn: config.ACCESS_TOKEN_TTL,
  });

  return {
    user,
    tokens,
  };
}

export async function loginUser(params: {
  prisma: PrismaClient;
  identifier: { email?: string; username?: string };
  password: string;
  deviceId?: string;
  signAccessToken: (payload: {
    sub: string;
    role: UserRole;
    username: string;
    languageId: string;
    expiresIn: number;
  }) => Promise<string>;
}): Promise<{
  tokens: TokenResponse;
  user: {
    id: string;
    email: string;
    username: string;
    role: UserRole;
    isActive: boolean;
  };
}> {
  const { prisma, identifier, password, deviceId, signAccessToken } = params;
  const { email, username } = identifier;

  const conditions = [
    email ? { email } : undefined,
    username ? { username } : undefined,
  ].filter((clause): clause is NonNullable<typeof clause> => Boolean(clause));

  if (!conditions.length) {
    throw new Error("Invalid credentials");
  }

  const user = await prisma.user.findFirst({
    where: {
      OR: conditions,
      isActive: true,
    },
  });

  if (!user) {
    throw new Error("Invalid credentials");
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    throw new Error("Invalid credentials");
  }

  const refreshToken = createRefreshToken();
  const tokens = await persistSession({
    prisma,
    userId: user.id,
    refreshToken,
    deviceId,
  });

  tokens.accessToken = await signAccessToken({
    sub: user.id,
    role: user.role,
    username: user.username,
    languageId: user.preferredLanguageId,
    expiresIn: config.ACCESS_TOKEN_TTL,
  });

  return {
    tokens,
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      isActive: user.isActive,
    },
  };
}

export async function issueTokensForUser(params: {
  prisma: PrismaClient;
  user: {
    id: string;
    role: UserRole;
    username: string;
    preferredLanguageId: string;
  };
  deviceId?: string;
  signAccessToken: (payload: {
    sub: string;
    role: UserRole;
    username: string;
    languageId: string;
    expiresIn: number;
  }) => Promise<string>;
}): Promise<TokenResponse> {
  const { prisma, user, deviceId, signAccessToken } = params;
  const refreshToken = createRefreshToken();
  const tokens = await persistSession({
    prisma,
    userId: user.id,
    refreshToken,
    deviceId,
  });

  tokens.accessToken = await signAccessToken({
    sub: user.id,
    role: user.role,
    username: user.username,
    languageId: user.preferredLanguageId,
    expiresIn: config.ACCESS_TOKEN_TTL,
  });

  return tokens;
}

export async function rotateRefreshToken(params: {
  prisma: PrismaClient;
  refreshToken: string;
  deviceId?: string;
  signAccessToken: (payload: {
    sub: string;
    role: UserRole;
    username: string;
    languageId: string;
    expiresIn: number;
  }) => Promise<string>;
}): Promise<TokenResponse> {
  const { prisma, refreshToken, deviceId, signAccessToken } = params;
  const hashedToken = hashToken(refreshToken);

  const session = await prisma.session.findFirst({
    where: { refreshTokenHash: hashedToken },
    include: {
      user: true,
    },
  });

  if (!session) {
    throw new AuthError("Invalid refresh token", "INVALID_REFRESH_TOKEN");
  }

  if (session.expiresAt.getTime() <= Date.now()) {
    await prisma.session.deleteMany({ where: { id: session.id } });
    throw new AuthError("Refresh token expired", "EXPIRED_REFRESH_TOKEN");
  }

  if (!session.user.isActive) {
    await prisma.session.deleteMany({ where: { id: session.id } });
    throw new AuthError("User disabled", "USER_DISABLED");
  }

  await prisma.session.deleteMany({ where: { id: session.id } });

  return issueTokensForUser({
    prisma,
    user: {
      id: session.user.id,
      role: session.user.role,
      username: session.user.username,
      preferredLanguageId: session.user.preferredLanguageId,
    },
    deviceId: deviceId ?? session.deviceId ?? undefined,
    signAccessToken,
  });
}

export async function revokeSessions(params: {
  prisma: PrismaClient;
  userId: string;
  refreshToken?: string;
  deviceId?: string;
  allDevices?: boolean;
}): Promise<void> {
  const { prisma, userId, refreshToken, deviceId, allDevices } = params;

  if (allDevices) {
    await prisma.session.deleteMany({ where: { userId } });
    return;
  }

  const conditions: Prisma.SessionWhereInput = {
    userId,
  };

  if (refreshToken) {
    conditions.refreshTokenHash = hashToken(refreshToken);
  }

  if (deviceId) {
    conditions.deviceId = deviceId;
  }

  await prisma.session.deleteMany({ where: conditions });
}
