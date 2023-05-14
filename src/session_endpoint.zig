const std = @import("std");
const zap = @import("zap");
const Sessions = @import("sessions.zig");
const Session = Sessions.Session;

// an Endpoint

pub const Self = @This();

alloc: std.mem.Allocator = undefined,
endpoint: zap.SimpleEndpoint = undefined,
sessions: Sessions = undefined,

pub fn init(
    a: std.mem.Allocator,
    session_path: []const u8,
) Self {
    return .{
        .alloc = a,
        .sessions = Sessions.init(a),
        .endpoint = zap.SimpleEndpoint.init(.{
            .path = session_path,
            .get = getSession,
            .post = postSession,
            .put = putSession,
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

fn sessionIdFromPath(self: *Self, path: []const u8) ?usize {
    if (path.len >= self.endpoint.settings.path.len + 2) {
        if (path[self.endpoint.settings.path.len] != '/') {
            return null;
        }
        const idstr = path[self.endpoint.settings.path.len + 1 ..];
        return std.fmt.parseUnsigned(usize, idstr, 10) catch null;
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

fn postSession(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.body) |body| {
        var stream = std.json.TokenStream.init(body);
        var maybe_session: ?Session = std.json.parse(Session, &stream, .{ .allocator = self.alloc }) catch null;
        if (maybe_session) |u| {
            defer std.json.parseFree(Session, u, .{ .allocator = self.alloc });
            if (self.sessions.addByName(u.first_name, u.last_name)) |id| {
                var jsonbuf: [128]u8 = undefined;
                if (zap.stringifyBuf(&jsonbuf, .{ .status = "OK", .id = id }, .{})) |json| {
                    r.sendJson(json) catch return;
                }
            } else |err| {
                std.debug.print("ADDING error: {}\n", .{err});
                return;
            }
        }
    }
}

fn putSession(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.path) |path| {
        if (self.sessionIdFromPath(path)) |id| {
            if (self.sessions.get(id)) |_| {
                if (r.body) |body| {
                    var stream = std.json.TokenStream.init(body);
                    var maybe_session: ?Session = std.json.parse(Session, &stream, .{ .allocator = self.alloc }) catch null;
                    if (maybe_session) |u| {
                        defer std.json.parseFree(Session, u, .{ .allocator = self.alloc });
                        var jsonbuf: [128]u8 = undefined;
                        if (self.sessions.update(id, u.first_name, u.last_name)) {
                            if (zap.stringifyBuf(&jsonbuf, .{ .status = "OK", .id = id }, .{})) |json| {
                                r.sendJson(json) catch return;
                            }
                        } else {
                            if (zap.stringifyBuf(&jsonbuf, .{ .status = "ERROR", .id = id }, .{})) |json| {
                                r.sendJson(json) catch return;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn deleteSession(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.path) |path| {
        if (self.sessionIdFromPath(path)) |id| {
            var jsonbuf: [128]u8 = undefined;
            if (self.sessions.delete(id)) {
                if (zap.stringifyBuf(&jsonbuf, .{ .status = "OK", .id = id }, .{})) |json| {
                    r.sendJson(json) catch return;
                }
            } else {
                if (zap.stringifyBuf(&jsonbuf, .{ .status = "ERROR", .id = id }, .{})) |json| {
                    r.sendJson(json) catch return;
                }
            }
        }
    }
}
