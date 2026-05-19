//! UI components — currently just the [`LoginPanel`].
//!
//! The catalog components ([`components::button::Button`] etc.) are
//! re-exported in case consumers want to compose their own panels.

pub mod components;
pub mod login_panel;

pub mod account;
pub mod admin;
pub mod permissions;

pub use account::AccountSettings;
pub use admin::{AdminRoleEditor, AdminRoleList, AdminUserDetail, AdminUserList, AuditLog};
pub use login_panel::{LoginPanel, LoginProvider, LoginSubmit, SubmitKind};
pub use permissions::{
    use_permissions, PermissionGate, PermissionSet, PermissionsProvider, Policy,
    RequirePermission, UsePermissions,
};
