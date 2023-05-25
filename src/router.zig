const std = @import("std");
const zap = @import("zap");
const Template = @import("template.zig");

pub fn Router(comptime Context: anytype) type {
    return struct {
        renderer: Template = undefined,
        endpoint: zap.SimpleEndpoint = undefined,
        gets: std.StringHashMap(RequestFn) = undefined,
        puts: std.StringHashMap(RequestFn) = undefined,
        posts: std.StringHashMap(RequestFn) = undefined,
        deletes: std.StringHashMap(RequestFn) = undefined,
        patches: std.StringHashMap(RequestFn) = undefined,

        pub const RequestFn = *const fn (Template, zap.SimpleRequest, *Context) bool;

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) !Self {
            return .{
                .endpoint = zap.SimpleEndpoint.init(.{
                    .path = "/", // doesn't matter
                    .get = handleRequest,
                    .post = handleRequest,
                    .put = handleRequest,
                    .delete = handleRequest,
                    .patch = handleRequest,
                }),
                .renderer = Template.init(allocator),
                .gets = std.StringHashMap(RequestFn).init(allocator),
                .posts = std.StringHashMap(RequestFn).init(allocator),
                .puts = std.StringHashMap(RequestFn).init(allocator),
                .deletes = std.StringHashMap(RequestFn).init(allocator),
                .patches = std.StringHashMap(RequestFn).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.renderer.deinit();
            self.gets.deinit();
            self.posts.deinit();
            self.puts.deinit();
            self.deletes.deinit();
            self.patches.deinit();
        }

        pub fn getEndpoint(self: *Self) *zap.SimpleEndpoint {
            return &self.endpoint;
        }

        pub fn get(self: *Self, path: []const u8, handler: RequestFn) !void {
            try self.gets.put(path, handler);
        }

        pub fn put(self: *Self, path: []const u8, handler: RequestFn) !void {
            try self.puts.put(path, handler);
        }

        pub fn post(self: *Self, path: []const u8, handler: RequestFn) !void {
            try self.posts.put(path, handler);
        }

        pub fn delete(self: *Self, path: []const u8, handler: RequestFn) !void {
            try self.deletes.put(path, handler);
        }

        pub fn patch(self: *Self, path: []const u8, handler: RequestFn) !void {
            try self.patches.put(path, handler);
        }

        pub fn handleRequest(ep: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            _ = dispatch(ep, r);
        }

        pub fn dispatch(ep: *zap.SimpleEndpoint, r: zap.SimpleRequest) bool {
            var self = @fieldParentPtr(Self, "endpoint", ep);

            std.debug.print("in dispatch:\n", .{});

            if (r.query) |query| {
                std.debug.print("QUERY: {s}\n", .{query});
            }

            if (r.path) |path| {
                std.debug.print("PATH: {s}\n", .{path});
                if (r.method) |method| {
                    std.debug.print("METHOD: {s}\n", .{method});

                    const maybe_context: ?*Context = r.getUserContext(Context);
                    if (maybe_context) |c| {
                        if (std.mem.eql(u8, method, "GET")) {
                            if (self.gets.get(path)) |handler| {
                                return handler(self.renderer, r, c);
                            }
                        } else if (std.mem.eql(u8, method, "POST")) {
                            if (self.posts.get(path)) |handler| {
                                return handler(self.renderer, r, c);
                            }
                        } else if (std.mem.eql(u8, method, "PUT")) {
                            if (self.puts.get(path)) |handler| {
                                return handler(self.renderer, r, c);
                            }
                        } else if (std.mem.eql(u8, method, "DELETE")) {
                            if (self.deletes.get(path)) |handler| {
                                return handler(self.renderer, r, c);
                            }
                        } else if (std.mem.eql(u8, method, "PATCH")) {
                            if (self.patches.get(path)) |handler| {
                                return handler(self.renderer, r, c);
                            }
                        }
                    }
                }
            }

            std.debug.print("in dispatch: 404 now\n", .{});
            r.setStatus(zap.StatusCode.not_found);
            r.sendBody("") catch return true;
            return true;
        }

        pub fn renderTemplate(self: *Self, r: zap.SimpleRequest, t: []const u8, m: anytype) !void {
            std.debug.print("rendering {s}\n", .{t});
            try self.renderer.render(r, t, m);
        }
    };
}
