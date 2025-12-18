import { z } from "zod";

export const adminLoginBodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const adminRegisterBodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const customerLoginBodySchema = z.object({
  firebaseToken: z.string().min(20),
  deviceId: z.string().min(3).max(128),
  guestId: z.string().min(3).max(128).optional(),
});

export const guestInitBodySchema = z.object({
  deviceId: z.string().min(3).max(128),
});

export const tokenResponseSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string(),
  expiresIn: z.number().int().positive(),
  refreshExpiresIn: z.number().int().positive(),
  tokenType: z.literal("Bearer").default("Bearer"),
});

export const guestInitResponseSchema = tokenResponseSchema.extend({
  guestId: z.string(),
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


export type AdminLoginBody = z.infer<typeof adminLoginBodySchema>;
export type AdminRegisterBody = z.infer<typeof adminRegisterBodySchema>;
export type CustomerLoginBody = z.infer<typeof customerLoginBodySchema>;
export type GuestInitBody = z.infer<typeof guestInitBodySchema>;
export type GuestInitResponse = z.infer<typeof guestInitResponseSchema>;
export type RefreshBody = z.infer<typeof refreshBodySchema>;
export type LogoutBody = z.infer<typeof logoutBodySchema>;
export type TokenResponse = z.infer<typeof tokenResponseSchema>;
