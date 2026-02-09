//! Configuration management for zgrnet.
//!
//! Handles parsing, validation, diffing, and hot-reloading of configuration files.
//! The config describes the "desired state" of the system; consumers receive
//! incremental diffs and reconcile accordingly.
//!
//! Zig uses JSON format; Go and Rust use YAML. The data structures are identical.

const std = @import("std");

pub const types = @import("types.zig");
pub const diff_mod = @import("diff.zig");
pub const route_mod = @import("route.zig");
pub const policy_mod = @import("policy.zig");
pub const manager_mod = @import("manager.zig");

// Re-export main types
pub const Config = types.Config;
pub const NetConfig = types.NetConfig;
pub const LanConfig = types.LanConfig;
pub const PeerConfig = types.PeerConfig;
pub const InboundPolicy = types.InboundPolicy;
pub const InboundRule = types.InboundRule;
pub const MatchConfig = types.MatchConfig;
pub const PubkeyMatch = types.PubkeyMatch;
pub const ServiceConfig = types.ServiceConfig;
pub const RouteConfig = types.RouteConfig;
pub const RouteRule = types.RouteRule;
pub const ConfigError = types.ConfigError;

pub const ConfigDiff = diff_mod.ConfigDiff;

pub const RouteMatcher = route_mod.RouteMatcher;
pub const RouteResult = route_mod.RouteResult;

pub const PolicyEngine = policy_mod.PolicyEngine;
pub const PolicyResult = policy_mod.PolicyResult;

pub const Manager = manager_mod.Manager;

test {
    std.testing.refAllDecls(@This());
    _ = types;
    _ = diff_mod;
    _ = route_mod;
    _ = policy_mod;
    _ = manager_mod;
}
