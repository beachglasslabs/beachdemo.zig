const std = @import("std");
const zap = @import("zap");
const Users = @import("users.zig");
const User = Users.User;
const Template = @import("template.zig");

pub fn UserEndpoint(comptime MovieManager: type, comptime Context: anytype) type {
    return struct {
        allocator: std.mem.Allocator = undefined,
        renderer: Template = undefined,
        endpoint: zap.SimpleEndpoint = undefined,
        movies: *MovieManager = undefined,
        users: Users = undefined,

        pub const Self = @This();

        pub fn init(
            a: std.mem.Allocator,
            user_path: []const u8,
            movies: *MovieManager,
        ) Self {
            return .{
                .allocator = a,
                .renderer = Template.init(a),
                .users = Users.init(a),
                .movies = movies,
                .endpoint = zap.SimpleEndpoint.init(.{
                    .path = user_path,
                    .get = getUser,
                    .post = updateFavorites,
                    .patch = updateFavorites,
                    .delete = updateFavorites,
                }),
            };
        }

        pub fn deinit(self: *Self) void {
            self.renderer.deinit();
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

        const prefix = "/users/favorites";

        fn movieIdFromPath(_: *Self, path: []const u8) ?[]const u8 {
            if (path.len >= prefix.len + 2) {
                if (path[prefix.len] != '/') {
                    return null;
                }
                return path[prefix.len + 1 ..];
            }
            return null;
        }

        fn getUser(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const self = @fieldParentPtr(Self, "endpoint", e);
            if (r.path) |path| {
                // /users
                if (path.len == e.settings.path.len) {
                    if (r.getUserContext(Context)) |c| {
                        return profiles(self.renderer, r, c);
                    }
                } else if (std.mem.eql(u8, path, prefix)) {
                    if (r.getUserContext(Context)) |c| {
                        if (c.user) |user| {
                            std.debug.print("favorites.get: user {s}\n", .{user.id});
                            const fav = self.users.getFavorites(user.id);
                            const json = std.json.stringifyAlloc(self.allocator, fav, .{}) catch return;
                            defer self.allocator.free(json);
                            r.sendJson(json) catch return;
                            return;
                        }
                    }
                }
            }
            r.setStatus(zap.StatusCode.not_found);
            r.sendBody("") catch return;
        }

        fn profiles(renderer: Template, r: zap.SimpleRequest, context: *Context) void {
            if (context.user) |user| {
                std.debug.print("profiles: user is {s}\n", .{user.name});
                renderer.render(r, "web/templates/profiles.html", .{ .name = user.name, .avatar = user.avatar }) catch return;
            } else {
                std.debug.print("profiles: user is null\n", .{});
            }
        }

        fn updateFavorites(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const self = @fieldParentPtr(Self, "endpoint", e);
            if (r.path) |path| {
                if (std.mem.startsWith(u8, path, prefix)) {
                    if (self.movieIdFromPath(path)) |id| {
                        if (r.getUserContext(Context)) |c| {
                            if (c.user) |user| {
                                const maybe_movie = self.movies.get(id);
                                if (maybe_movie) |movie| {
                                    if (r.method) |method| {
                                        if (std.mem.eql(u8, method, "POST")) {
                                            const fav = self.users.addFavorite(user.id, movie);
                                            const json = std.json.stringifyAlloc(self.allocator, fav, .{}) catch return;
                                            defer self.allocator.free(json);
                                            r.sendJson(json) catch return;
                                            return;
                                        } else if (std.mem.eql(u8, method, "DELETE")) {
                                            const fav = self.users.removeFavorite(user.id, movie);
                                            const json = std.json.stringifyAlloc(self.allocator, fav, .{}) catch return;
                                            defer self.allocator.free(json);
                                            r.sendJson(json) catch return;
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    };
}
