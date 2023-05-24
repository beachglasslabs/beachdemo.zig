const std = @import("std");
const zap = @import("zap");
const Users = @import("users.zig");
const User = Users.User;

// an Endpoint

pub const Self = @This();

allocator: std.mem.Allocator = undefined,
endpoint: zap.SimpleEndpoint = undefined,
users: Users = undefined,

pub fn init(
    a: std.mem.Allocator,
    user_path: []const u8,
) Self {
    return .{
        .allocator = a,
        .users = Users.init(a),
        .endpoint = zap.SimpleEndpoint.init(.{
            .path = user_path,
            .get = getUser,
            .patch = updateUser,
            .delete = deleteUser,
        }),
    };
}

pub fn deinit(self: *Self) void {
    self.users.deinit();
}

pub fn getBySub(self: *Self, sub: []const u8) ?User {
    return self.users.getByEmail(sub);
}

pub fn get(self: *Self, id: []const u8) ?User {
    return self.users.getById(id);
}

pub const UserError = error{
    InvalidEmailError,
    InvalidPasswordError,
    InvalidNameError,
};

pub fn post(self: *Self, name: ?[]const u8, email: ?[]const u8, password: ?[]const u8) ![]const u8 {
    const username = name orelse return error.InvalidNameError;
    const usermail = email orelse return error.InvalidEmailError;
    const userpass = password orelse return error.InvalidPasswordError;

    return self.users.add(username, usermail, userpass);
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
        if (self.userIdFromPath(path)) |id| {
            if (self.users.getById(id)) |user| {
                const json = std.json.stringifyAlloc(self.allocator, user, .{}) catch return;
                defer self.allocator.free(json);
                r.sendJson(json) catch return;
            }
        }
    }
}

fn listUsers(self: *Self, r: zap.SimpleRequest) void {
    if (self.users.toJSON()) |json| {
        defer self.allocator.free(json);
        r.sendJson(json) catch return;
    } else |err| {
        std.debug.print("LIST error: {}\n", .{err});
    }
}

fn updateUser(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.path) |path| {
        if (self.userIdFromPath(path)) |id| {
            if (self.users.getById(id)) |_| {
                if (r.body) |_| {}
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
