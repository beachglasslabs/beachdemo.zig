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
            //.patch = updateUser,
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

fn userIdFromPath(self: *Self, path: []const u8) ?usize {
    if (path.len >= self.endpoint.settings.path.len + 2) {
        if (path[self.endpoint.settings.path.len] != '/') {
            return null;
        }
        const idstr = path[self.endpoint.settings.path.len + 1 ..];
        return std.fmt.parseUnsigned(usize, idstr, 10) catch null;
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
    };

    // check for query parameters
    r.parseQuery();

    var param_count = r.getParamCount();
    std.log.info("param_count: {}", .{param_count});

    var name = std.mem.zeroes([64]u8);
    var email = std.mem.zeroes([64]u8);
    var password = std.mem.zeroes([64]u8);

    if (r.getParamStr("name", self.alloc, false)) |maybe_str| {
        if (maybe_str) |*s| {
            defer s.deinit();

            std.mem.copy(u8, name[0..], s.str);
            std.log.info("Param name = {s}", .{s.str});
        } else {
            std.log.info("Param name not found!", .{});
        }
    } else |err| {
        std.log.err("cannot check for `name` param: {any}\n", .{err});
    }

    if (r.getParamStr("email", self.alloc, false)) |maybe_str| {
        if (maybe_str) |*s| {
            defer s.deinit();

            std.mem.copy(u8, email[0..], s.str);
            std.log.info("Param email = {s}", .{s.str});
        } else {
            std.log.info("Param email not found!", .{});
        }
    } else |err| {
        std.log.err("cannot check for `email` param: {any}\n", .{err});
    }

    if (r.getParamStr("password", self.alloc, false)) |maybe_str| {
        if (maybe_str) |*s| {
            defer s.deinit();

            std.mem.copy(u8, password[0..], s.str);
            std.log.info("Param password = {s}", .{s.str});
        } else {
            std.log.info("Param password not found!", .{});
        }
    } else |err| {
        std.log.err("cannot check for `password` param: {any}\n", .{err});
    }

    std.debug.print("name={s}, email={s}, password={s}\n", .{ name, email, password });

    if (self.users.add(&name, &email, &password)) |id| {
        std.debug.print("{s} logged in as user {d}", .{ email, id });
    } else |err| {
        std.debug.print("ADDING error: {}\n", .{err});
        return;
    }

    const json = self.users.toJSON() catch return;
    std.debug.print("users: {s}\n", .{json});
}

fn updateUser(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.path) |path| {
        if (self.userIdFromPath(path)) |id| {
            if (self.users.get(id)) |_| {
                if (r.body) |body| {
                    var stream = std.json.TokenStream.init(body);
                    var maybe_user: ?User = std.json.parse(User, &stream, .{ .allocator = self.alloc }) catch null;
                    if (maybe_user) |u| {
                        defer std.json.parseFree(User, u, .{ .allocator = self.alloc });
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
