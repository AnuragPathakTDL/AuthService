import path from "node:path";
import * as grpc from "@grpc/grpc-js";
import { loadSync } from "@grpc/proto-loader";
import fp from "fastify-plugin";
import type { FastifyInstance } from "fastify";
import { loadConfig } from "../config";
import type {
  UserServiceAssignment,
  UserServiceContext,
  UserServiceIntegration,
  UserServicePermission,
  UserServiceRole,
  EnsureCustomerProfileResult,
  RegisterGuestResult,
  GuestProfileStatus,
} from "../types/user-service";

type PermissionMessage = {
  id: string;
  resource: string;
  action: string;
  description?: string;
};

type RoleMessage = {
  id: string;
  name: string;
  description?: string;
  permissions: PermissionMessage[];
};

type AssignmentMessage = {
  assignment_id: string;
  user_id: string;
  scope?: string;
  granted_by?: string;
  active: boolean;
  role?: RoleMessage;
};

type GetUserContextRequest = {
  user_id: string;
};

type GetUserContextResponse = {
  user_id: string;
  roles?: RoleMessage[];
  permissions?: PermissionMessage[];
  assignments?: AssignmentMessage[];
};

type AssignRoleRequest = {
  user_id: string;
  role_id: string;
  scope?: string;
  granted_by?: string;
};

type AssignRoleResponse = {
  success: boolean;
  assignment?: AssignmentMessage;
};

type RevokeRoleRequest = {
  assignment_id: string;
  revoked_by?: string;
};

type RevokeRoleResponse = {
  success: boolean;
};

type ListRolesRequest = Record<string, never>;

type ListRolesResponse = {
  roles: RoleMessage[];
};

type EnsureCustomerProfileRequest = {
  firebase_uid: string;
  phone_number?: string;
  device_id: string;
  guest_id?: string;
};

type EnsureCustomerProfileResponse = {
  customer_id: string;
  device_identity_id: string;
  guest_migrated: boolean;
  guest_profile_id?: string;
};

enum GuestProfileStatusMessage {
  GUEST_PROFILE_STATUS_UNSPECIFIED = 0,
  GUEST_PROFILE_STATUS_ACTIVE = 1,
  GUEST_PROFILE_STATUS_MIGRATED = 2,
}

type RegisterGuestRequest = {
  guest_id: string;
  device_id: string;
};

type RegisterGuestResponse = {
  guest_profile_id: string;
  device_identity_id: string;
  status: GuestProfileStatusMessage;
  customer_id?: string;
};

type GrpcUnary<Req, Res> = (
  request: Req,
  metadata: grpc.Metadata,
  callback: (error: grpc.ServiceError | null, response: Res) => void
) => void;

type UserPackageDefinition = ReturnType<typeof grpc.loadPackageDefinition> & {
  user: {
    v1: {
      UserService: grpc.ServiceClientConstructor & {
        service: grpc.ServiceDefinition;
      };
    };
  };
};

type GrpcUserServiceClient = grpc.Client & {
  GetUserContext: GrpcUnary<GetUserContextRequest, GetUserContextResponse>;
  AssignRole: GrpcUnary<AssignRoleRequest, AssignRoleResponse>;
  RevokeRole: GrpcUnary<RevokeRoleRequest, RevokeRoleResponse>;
  ListRoles: GrpcUnary<ListRolesRequest, ListRolesResponse>;
  EnsureCustomerProfile: GrpcUnary<
    EnsureCustomerProfileRequest,
    EnsureCustomerProfileResponse
  >;
  RegisterGuest: GrpcUnary<RegisterGuestRequest, RegisterGuestResponse>;
};

const PROTO_PATH = path.join(__dirname, "../../proto/user.proto");

function loadUserPackage(): UserPackageDefinition["user"]["v1"] {
  const definition = loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const loaded = grpc.loadPackageDefinition(
    definition
  ) as UserPackageDefinition;
  return loaded.user.v1;
}

function mapPermission(message: PermissionMessage): UserServicePermission {
  return {
    id: message.id,
    resource: message.resource,
    action: message.action,
    description:
      message.description && message.description.length > 0
        ? message.description
        : undefined,
  };
}

function mapRole(message: RoleMessage): UserServiceRole {
  return {
    id: message.id,
    name: message.name,
    description:
      message.description && message.description.length > 0
        ? message.description
        : undefined,
    permissions: (message.permissions ?? []).map(mapPermission),
  };
}

function mapAssignment(message: AssignmentMessage): UserServiceAssignment {
  if (!message.role) {
    throw new Error("UserService assignment response missing role data");
  }
  return {
    assignmentId: message.assignment_id,
    userId: message.user_id,
    scope:
      message.scope && message.scope.length > 0 ? message.scope : undefined,
    grantedBy:
      message.granted_by && message.granted_by.length > 0
        ? message.granted_by
        : undefined,
    active: message.active,
    role: mapRole(message.role),
  };
}

function mapContext(response: GetUserContextResponse): UserServiceContext {
  return {
    userId: response.user_id,
    roles: (response.roles ?? []).map(mapRole),
    permissions: (response.permissions ?? []).map(mapPermission),
    assignments: (response.assignments ?? []).map(mapAssignment),
  };
}

function mapGuestStatus(
  status: GuestProfileStatusMessage | undefined
): GuestProfileStatus {
  switch (status) {
    case GuestProfileStatusMessage.GUEST_PROFILE_STATUS_ACTIVE:
      return "ACTIVE";
    case GuestProfileStatusMessage.GUEST_PROFILE_STATUS_MIGRATED:
      return "MIGRATED";
    default:
      return "ACTIVE";
  }
}

function createMetadata(token?: string) {
  const metadata = new grpc.Metadata();
  if (token) {
    metadata.set("authorization", `Bearer ${token}`);
  }
  return metadata;
}

function wrapUnary<Req, Res>(method: GrpcUnary<Req, Res>, token?: string) {
  return (request: Req): Promise<Res> => {
    return new Promise<Res>((resolve, reject) => {
      const metadata = createMetadata(token);
      method(request, metadata, (error, response) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(response);
      });
    });
  };
}

const userServicePlugin = fp(async function userServicePlugin(
  fastify: FastifyInstance
) {
  const integration: UserServiceIntegration = {
    isEnabled: false,
    async getUserContext() {
      throw new Error("UserService integration disabled");
    },
    async assignRole() {
      throw new Error("UserService integration disabled");
    },
    async revokeRole() {
      throw new Error("UserService integration disabled");
    },
    async listRoles() {
      throw new Error("UserService integration disabled");
    },
    async ensureCustomerProfile() {
      throw new Error("UserService integration disabled");
    },
    async registerGuest() {
      throw new Error("UserService integration disabled");
    },
  };

  fastify.decorate("userService", integration);

  const config = loadConfig();
  if (!config.USER_SERVICE_ADDRESS) {
    fastify.log.warn(
      "USER_SERVICE_ADDRESS not configured; RBAC integration disabled"
    );
    return;
  }

  const userPackage = loadUserPackage();
  const client = new userPackage.UserService(
    config.USER_SERVICE_ADDRESS,
    grpc.credentials.createInsecure()
  ) as unknown as GrpcUserServiceClient;

  const getUserContextUnary = wrapUnary(
    client.GetUserContext.bind(client),
    config.USER_SERVICE_TOKEN
  );
  const assignRoleUnary = wrapUnary(
    client.AssignRole.bind(client),
    config.USER_SERVICE_TOKEN
  );
  const revokeRoleUnary = wrapUnary(
    client.RevokeRole.bind(client),
    config.USER_SERVICE_TOKEN
  );
  const listRolesUnary = wrapUnary(
    client.ListRoles.bind(client),
    config.USER_SERVICE_TOKEN
  );
  const ensureCustomerProfileUnary = wrapUnary(
    client.EnsureCustomerProfile.bind(client),
    config.USER_SERVICE_TOKEN
  );
  const registerGuestUnary = wrapUnary(
    client.RegisterGuest.bind(client),
    config.USER_SERVICE_TOKEN
  );

  Object.assign(integration, {
    isEnabled: true,
    async getUserContext(userId: string) {
      const response = await getUserContextUnary({ user_id: userId });
      return mapContext(response);
    },
    async assignRole(params: {
      userId: string;
      roleId: string;
      scope?: string;
      grantedBy?: string;
    }) {
      await assignRoleUnary({
        user_id: params.userId,
        role_id: params.roleId,
        scope: params.scope,
        granted_by: params.grantedBy,
      });
    },
    async revokeRole(params: { assignmentId: string; revokedBy?: string }) {
      await revokeRoleUnary({
        assignment_id: params.assignmentId,
        revoked_by: params.revokedBy,
      });
    },
    async listRoles() {
      const response = await listRolesUnary({});
      return response.roles.map(mapRole);
    },
    async ensureCustomerProfile(params: {
      firebaseUid: string;
      phoneNumber?: string;
      deviceId: string;
      guestId?: string;
    }): Promise<EnsureCustomerProfileResult> {
      const response = await ensureCustomerProfileUnary({
        firebase_uid: params.firebaseUid,
        phone_number: params.phoneNumber,
        device_id: params.deviceId,
        guest_id: params.guestId,
      });
      return {
        customerId: response.customer_id,
        deviceIdentityId: response.device_identity_id,
        guestMigrated: response.guest_migrated,
        guestProfileId:
          response.guest_profile_id && response.guest_profile_id.length > 0
            ? response.guest_profile_id
            : undefined,
      } satisfies EnsureCustomerProfileResult;
    },
    async registerGuest(params: {
      guestId: string;
      deviceId: string;
    }): Promise<RegisterGuestResult> {
      const response = await registerGuestUnary({
        guest_id: params.guestId,
        device_id: params.deviceId,
      });
      return {
        guestProfileId: response.guest_profile_id,
        deviceIdentityId: response.device_identity_id,
        status: mapGuestStatus(response.status),
        customerId:
          response.customer_id && response.customer_id.length > 0
            ? response.customer_id
            : undefined,
      } satisfies RegisterGuestResult;
    },
  } as UserServiceIntegration);

  fastify.addHook("onClose", async () => {
    client.close();
  });
});

declare module "fastify" {
  interface FastifyInstance {
    userService: UserServiceIntegration;
  }
}

export default userServicePlugin;
