export interface UserServicePermission {
  id: string;
  resource: string;
  action: string;
  description?: string;
}

export interface UserServiceRole {
  id: string;
  name: string;
  description?: string;
  permissions: UserServicePermission[];
}

export interface UserServiceAssignment {
  assignmentId: string;
  userId: string;
  role: UserServiceRole;
  scope?: string;
  grantedBy?: string;
  active: boolean;
}

export interface UserServiceContext {
  userId: string;
  roles: UserServiceRole[];
  permissions: UserServicePermission[];
  assignments: UserServiceAssignment[];
}

export interface UserServiceIntegration {
  isEnabled: boolean;
  getUserContext(userId: string): Promise<UserServiceContext>;
  assignRole(params: {
    userId: string;
    roleId: string;
    scope?: string;
    grantedBy?: string;
  }): Promise<void>;
  revokeRole(params: {
    assignmentId: string;
    revokedBy?: string;
  }): Promise<void>;
  listRoles(): Promise<UserServiceRole[]>;
}
