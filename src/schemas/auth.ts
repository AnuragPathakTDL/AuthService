import { z } from "zod";

export const userRoleSchema = z.enum(["ADMIN", "CUSTOMER"]);

export const languageIdSchema = z.string().min(1);

export const registerBodySchema = z.object({
  email: z.string().email(),
  username: z.string().min(3).max(64),
  password: z.string().min(8),
  role: userRoleSchema.optional(),
  deviceId: z.string().min(3).max(128).optional(),
  preferredLanguageId: languageIdSchema.optional(),
});

export const loginBodySchema = z
  .object({
    email: z.string().email().optional(),
    username: z.string().min(3).max(64).optional(),
    password: z.string().min(8),
    deviceId: z.string().min(3).max(128).optional(),
  })
  .refine((value) => Boolean(value.email || value.username), {
    message: "Provide either email or username",
    path: ["username"],
  });

export const refreshBodySchema = z.object({
  refreshToken: z.string().min(1),
  deviceId: z.string().min(3).max(128).optional(),
});

export const logoutBodySchema = z
  .object({
    refreshToken: z.string().min(1).optional(),
    deviceId: z.string().min(3).max(128).optional(),
    allDevices: z.boolean().optional(),
  })
  .refine(
    (value) =>
      Boolean(value.allDevices || value.refreshToken || value.deviceId),
    {
      message: "Provide refreshToken, deviceId, or set allDevices to true",
      path: ["refreshToken"],
    }
  );

export const updateLanguageBodySchema = z.object({
  preferredLanguageId: languageIdSchema,
});

export const oauthPasswordBodySchema = z
  .object({
    grant_type: z.literal("password"),
    username: z.string().min(3).max(128),
    password: z.string().min(8),
    scope: z.string().optional(),
    device_id: z.string().min(3).max(128).optional(),
  })
  .transform((value) => ({
    ...value,
    username: value.username.trim(),
  }));

export const tokenResponseSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string(),
  expiresIn: z.number().int().positive(),
  refreshExpiresIn: z.number().int().positive(),
  tokenType: z.literal("Bearer").default("Bearer"),
});

export const publicUserSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  username: z.string(),
  role: userRoleSchema,
  preferredLanguageId: languageIdSchema,
  createdAt: z.string(),
  updatedAt: z.string(),
});

export const registerResponseSchema = z.object({
  user: publicUserSchema,
  tokens: tokenResponseSchema,
});

export type RegisterBody = z.infer<typeof registerBodySchema>;
export type LoginBody = z.infer<typeof loginBodySchema>;
export type OAuthPasswordBody = z.infer<typeof oauthPasswordBodySchema>;
export type RefreshBody = z.infer<typeof refreshBodySchema>;
export type LogoutBody = z.infer<typeof logoutBodySchema>;
export type TokenResponse = z.infer<typeof tokenResponseSchema>;
export type RegisterResponse = z.infer<typeof registerResponseSchema>;
