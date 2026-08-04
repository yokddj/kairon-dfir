# Roles and Permissions

Kairon DFIR uses two roles:

- **Administrator**
- **Standard user**

Both roles can use all investigation features (Search, Timeline, Findings, Evidence upload, etc.). The only difference is access to user management.

## Permission Matrix

| Capability | Administrator | Standard user |
|------------|--------------|---------------|
| Use Kairon | Yes | Yes |
| Change own password | Yes | Yes |
| View users | Yes | No |
| Create users | Yes | No |
| Edit users | Yes | No |
| Disable users | Yes | No |
| Reset passwords | Yes | No |
| Revoke sessions | Yes | No |
| Promote/demote users | Yes | No |

## Administrator

The administrator role is for operators who need to manage the platform and its users.

Administrators can:
- Use all Kairon investigation features.
- Access **Admin → Users**.
- Create, edit, enable, and disable user accounts.
- Reset passwords for other users.
- Revoke sessions for other users.
- Change their own password.

Administrators cannot:
- Disable or demote themselves if they are the last active administrator.

## Standard User

Standard users have full access to Kairon's investigation features but cannot manage other users.

Standard users can:
- Investigate cases.
- Upload evidence.
- Use Search, Timeline, Findings, Memory, and all other tools.
- Change their own password.

Standard users cannot:
- Access **Admin → Users**.
- View the user list.
- Create, edit, disable, or enable other users.
- Reset other users' passwords.
- Revoke other users' sessions.

## Last Administrator Protection

The last active administrator cannot be disabled or demoted to a standard user. This prevents accidental lockout. If you need to remove the last administrator, first promote another user to administrator.

## What Is Not Active in This Beta

- **Per-case user assignment** is not enabled. All authenticated users can access all cases.
- There is no read-only or viewer role. Both roles have full investigation capabilities.
- There is no analyst role. Standard users have the same access as what was previously called "analyst".

## Changing Your Password

Both roles can change their own password from **My Account → Change Password**. You must provide your current password and a new password (minimum 12 characters).
