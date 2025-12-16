import { PrismaClient, UserRole } from "@prisma/client";
import { randomBytes, createHash } from "node:crypto";
import { loadConfig } from "../config";
import type { TokenResponse } from "../schemas/auth";
import { hashPassword, verifyPassword } from "../utils/password";

const config = loadConfig();

function hashToken(token: string): string {
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
  deviceId?: string;
  signAccessToken: (payload: {
    sub: string;
    role: UserRole;
    username: string;
    expiresIn: number;
  }) => Promise<string>;
}): Promise<{
  user: {
    id: string;
    email: string;
    username: string;
    role: UserRole;
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
