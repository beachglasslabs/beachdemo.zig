const std = @import("std");
const zap = @import("zap");
const Sessions = @import("sessions.zig");
const Session = Sessions.Session;
const Users = @import("users.zig");

// an Endpoint

pub const Self = @This();

alloc: std.mem.Allocator = undefined,
endpoint: zap.SimpleEndpoint = undefined,
sessions: Sessions = undefined,
users: *Users = undefined,

pub fn init(
    a: std.mem.Allocator,
    session_path: []const u8,
    u: *Users,
) Self {
    return .{
        .alloc = a,
        .sessions = Sessions.init(a),
        .users = u,
        .endpoint = zap.SimpleEndpoint.init(.{
            .path = session_path,
            .get = getSession,
            .delete = deleteSession,
        }),
    };
}

pub fn deinit(self: *Self) void {
    self.sessions.deinit();
}

pub fn getSessions(self: *Self) *Sessions {
    return &self.sessions;
}

pub fn getEndpoint(self: *Self) *zap.SimpleEndpoint {
    return &self.endpoint;
}

fn sessionIdFromPath(self: *Self, path: []const u8) ?[]const u8 {
    if (path.len >= self.endpoint.settings.path.len + 2) {
        if (path[self.endpoint.settings.path.len] != '/') {
            return null;
        }
        return path[self.endpoint.settings.path.len + 1 ..];
    }
    return null;
}

fn getSession(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.path) |path| {
        // /sessions
        if (path.len == e.settings.path.len) {
            return self.listSessions(r);
        }
        var jsonbuf: [256]u8 = undefined;
        if (self.sessionIdFromPath(path)) |id| {
            if (self.sessions.get(id)) |session| {
                if (zap.stringifyBuf(&jsonbuf, session, .{})) |json| {
                    r.sendJson(json) catch return;
                }
            }
        }
    }
}

fn listSessions(self: *Self, r: zap.SimpleRequest) void {
    if (self.sessions.toJSON()) |json| {
        defer self.alloc.free(json);
        r.sendJson(json) catch return;
    } else |err| {
        std.debug.print("LIST error: {}\n", .{err});
    }
}

fn deleteSession(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    std.debug.print("deleting session\n", .{});
    if (r.path) |path| {
        std.debug.print("deleting path {s}\n", .{path});
        if (self.sessionIdFromPath(path)) |id| {
            if (self.sessions.delete(id)) {
                return r.redirectTo("/auth", zap.StatusCode.see_other) catch return;
            } else {
                return r.redirectTo("/auth", zap.StatusCode.see_other) catch return;
            }
        }
    }
    return r.redirectTo("/auth", zap.StatusCode.see_other) catch return;
}
