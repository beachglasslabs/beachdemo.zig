const std = @import("std");
const zap = @import("zap");
const Users = @import("users.zig");
const User = Users.User;

// an Endpoint

pub const Self = @This();

alloc: std.mem.Allocator = undefined,
endpoint: zap.SimpleEndpoint = undefined,
users: Users = undefined,

pub fn init(
    a: std.mem.Allocator,
    user_path: []const u8,
) Self {
    return .{
        .alloc = a,
        .users = Users.init(a),
        .endpoint = zap.SimpleEndpoint.init(.{
            .path = user_path,
            .get = getUser,
            .post = addUser,
            .put = updateUser,
            .patch = updateUser,
            .delete = deleteUser,
        }),
    };
}

pub fn deinit(self: *Self) void {
    self.users.deinit();
}

pub fn getUsers(self: *Self) *Users {
    return &self.users;
}

pub fn getEndpoint(self: *Self) *zap.SimpleEndpoint {
    return &self.endpoint;
}

fn userIdFromPath(self: *Self, path: []const u8) ?[]const u8 {
    if (path.len >= self.endpoint.settings.path.len + 2) {
        if (path[self.endpoint.settings.path.len] != '/') {
            return null;
        }
        return path[self.endpoint.settings.path.len + 1 ..];
    }
    return null;
}

fn getUser(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.path) |path| {
        // /users
        if (path.len == e.settings.path.len) {
            return self.listUsers(r);
        }
        var jsonbuf: [256]u8 = undefined;
        if (self.userIdFromPath(path)) |id| {
            if (self.users.get(id)) |user| {
                if (zap.stringifyBuf(&jsonbuf, user, .{})) |json| {
                    r.sendJson(json) catch return;
                }
            }
        }
    }
}

fn listUsers(self: *Self, r: zap.SimpleRequest) void {
    if (self.users.toJSON()) |json| {
        defer self.alloc.free(json);
        r.sendJson(json) catch return;
    } else |err| {
        std.debug.print("LIST error: {}\n", .{err});
    }
}

fn addUser(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);

    // check for FORM parameters
    r.parseBody() catch |err| {
        std.log.err("Parse Body error: {any}. Expected if body is empty", .{err});
        r.redirectTo("/auth", zap.StatusCode.found) catch return;
    };

    // check for query parameters
    r.parseQuery();

    var param_count = r.getParamCount();
    std.log.info("param count: {}", .{param_count});

    var name: ?[]const u8 = null;
    var email: ?[]const u8 = null;
    var password: ?[]const u8 = null;

    var strparams = r.parametersToOwnedStrList(self.alloc, false) catch unreachable;
    defer strparams.deinit();
    std.debug.print("\n", .{});
    for (strparams.items) |kv| {
        std.log.info("ParamStr `{s}` is `{s}`", .{ kv.key.str, kv.value.str });
        if (std.mem.eql(u8, "name", kv.key.str)) {
            name = kv.value.str;
        }
        if (std.mem.eql(u8, "email", kv.key.str)) {
            email = kv.value.str;
        }
        if (std.mem.eql(u8, "password", kv.key.str)) {
            password = kv.value.str;
        }
    }

    std.log.info("name={s}, email={s}, password={s}\n", .{ name.?, email.?, password.? });

    if (self.users.add(name, email, password)) |id| {
        std.log.info("{s} registered as user {s}\n", .{ email.?, id });
        r.redirectTo("/", zap.StatusCode.found) catch return;
    } else |err| {
        std.debug.print("ADDING error: {}\n", .{err});
        return;
    }
}

fn updateUser(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.path) |path| {
        if (self.userIdFromPath(path)) |id| {
            if (self.users.get(id)) |_| {
                if (r.body) |body| {
                    var maybe_user: ?User = std.json.parseFromSlice(User, self.alloc, body, .{}) catch null;
                    if (maybe_user) |u| {
                        defer std.json.parseFree(User, self.alloc, u);
                        var jsonbuf: [128]u8 = undefined;
                        if (self.users.update(id, u.name, u.email, u.password)) {
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

fn deleteUser(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.path) |path| {
        if (self.userIdFromPath(path)) |id| {
            var jsonbuf: [128]u8 = undefined;
            if (self.users.delete(id)) {
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
