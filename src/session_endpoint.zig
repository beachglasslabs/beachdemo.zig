const std = @import("std");
const zap = @import("zap");
const Sessions = @import("sessions.zig");
const Session = Sessions.Session;
const Users = @import("users.zig");

// an Endpoint

pub const Self = @This();

allocator: std.mem.Allocator = undefined,
endpoint: zap.SimpleEndpoint = undefined,
sessions: Sessions = undefined,

pub fn init(
    a: std.mem.Allocator,
    session_path: []const u8,
) Self {
    return .{
        .allocator = a,
        .sessions = Sessions.init(a),
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

pub fn get(self: *Self, id: []const u8) ?Session {
    return self.sessions.get(id);
}

pub fn delete(self: *Self, id: []const u8) bool {
    return self.sessions.delete(id);
}

pub fn post(self: *Self, userid: []const u8) ![]const u8 {
    return self.sessions.create(userid);
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
        if (self.sessionIdFromPath(path)) |id| {
            if (self.sessions.get(id)) |session| {
                const json = std.json.stringifyAlloc(self.allocator, session, .{}) catch return;
                defer self.allocator.free(json);
                r.sendJson(json) catch return;
                return;
            }
        }
    }
    r.setStatus(zap.StatusCode.not_found);
    r.sendJson("") catch return;
}

fn listSessions(self: *Self, r: zap.SimpleRequest) void {
    if (self.sessions.toJSON()) |json| {
        defer self.allocator.free(json);
        r.sendJson(json) catch return;
    } else |err| {
        std.debug.print("LIST error: {}\n", .{err});
    }
}

fn deleteSession(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    std.debug.print("session: deleting\n", .{});
    if (r.path) |path| {
        std.debug.print("session: deleting path {s}\n", .{path});
        if (self.sessionIdFromPath(path)) |id| {
            _ = self.delete(id);
        }
    }
    return r.redirectTo(self.endpoint.settings.path, zap.StatusCode.see_other) catch return;
}
