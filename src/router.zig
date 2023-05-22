const std = @import("std");
const zap = @import("zap");

pub fn Router(comptime ContextType: anytype) type {
    return struct {
        allocator: std.mem.Allocator = undefined,
        gets: std.StringHashMap(RequestFn) = undefined,
        puts: std.StringHashMap(RequestFn) = undefined,
        posts: std.StringHashMap(RequestFn) = undefined,
        deletes: std.StringHashMap(RequestFn) = undefined,
        patches: std.StringHashMap(RequestFn) = undefined,

        pub const RequestFn = *const fn (*Self, zap.SimpleRequest, ?ContextType) void;
        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) !Self {
            return .{
                .allocator = allocator,
                .gets = std.StringHashMap(RequestFn).init(allocator),
                .posts = std.StringHashMap(RequestFn).init(allocator),
                .puts = std.StringHashMap(RequestFn).init(allocator),
                .deletes = std.StringHashMap(RequestFn).init(allocator),
                .patches = std.StringHashMap(RequestFn).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            self.gets.deinit();
            self.posts.deinit();
            self.puts.deinit();
            self.deletes.deinit();
            self.patches.deinit();
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

        pub fn dispatch(self: *Self, r: zap.SimpleRequest, c: ?ContextType) void {
            std.debug.print("in dispatch:\n", .{});
            if (r.query) |query| {
                std.debug.print("QUERY: {s}\n", .{query});
            }

            if (r.path) |path| {
                std.debug.print("PATH: {s}\n", .{path});
                if (r.method) |method| {
                    std.debug.print("METHOD: {s}\n", .{method});
                    if (std.mem.eql(u8, method, "GET")) {
                        if (self.gets.get(path)) |handler| {
                            return handler(self, r, c);
                        }
                    } else if (std.mem.eql(u8, method, "POST")) {
                        if (self.posts.get(path)) |handler| {
                            return handler(self, r, c);
                        }
                    } else if (std.mem.eql(u8, method, "PUT")) {
                        if (self.puts.get(path)) |handler| {
                            return handler(self, r, c);
                        }
                    } else if (std.mem.eql(u8, method, "DELETE")) {
                        if (self.deletes.get(path)) |handler| {
                            return handler(self, r, c);
                        }
                    } else if (std.mem.eql(u8, method, "PATCH")) {
                        if (self.patches.get(path)) |handler| {
                            return handler(self, r, c);
                        }
                    }
                }
            }

            std.debug.print("in dispatch: 404 now\n", .{});
            r.setStatus(zap.StatusCode.not_found);
            r.sendBody("") catch return;
        }

        pub fn renderTemplate(self: *Self, r: zap.SimpleRequest, t: []const u8, m: anytype) !void {
            const file = try std.fs.cwd().openFile(
                t,
                .{},
            );
            defer file.close();

            const size = (try file.stat()).size;

            const template = try file.reader().readAllAlloc(self.allocator, size);
            defer self.allocator.free(template);

            const p = try zap.MustacheNew(template);
            defer zap.MustacheFree(p);
            const ret = zap.MustacheBuild(p, m);
            defer ret.deinit();
            if (r.setContentType(.HTML)) {
                if (ret.str()) |resp| {
                    r.setStatus(zap.StatusCode.ok);
                    try r.sendBody(resp);
                } else {
                    r.setStatus(zap.StatusCode.not_found);
                    try r.sendBody("");
                }
            } else |err| return err;
            return;
        }
    };
}
