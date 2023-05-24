const std = @import("std");
const zap = @import("zap");

/// Wrap multiple endpoints
pub fn Middleware(comptime Router: type, comptime Authenticator: type) type {
    return struct {
        allocator: std.mem.Allocator,
        endpoints: std.ArrayList(*zap.SimpleEndpoint),
        authenticator: *Authenticator,
        router: *Router,
        fascade: zap.SimpleEndpoint,

        pub const RequestFn = *const fn (*zap.SimpleEndpoint, zap.SimpleRequest) void;
        const Self = @This();

        pub fn init(a: std.mem.Allocator, router: *Router, authenticator: *Authenticator) Self {
            return .{
                .allocator = a,
                .authenticator = authenticator,
                .endpoints = std.ArrayList(*zap.SimpleEndpoint).init(a),
                .router = router,
                .fascade = zap.SimpleEndpoint.init(.{
                    .path = "/", // we do everything
                    .get = handleRequest,
                    .post = handleRequest,
                    .put = handleRequest,
                    .delete = handleRequest,
                    .patch = handleRequest,
                }),
            };
        }

        pub fn deinit(self: *Self) void {
            self.endpoints.deinit();
        }

        /// get the mega endpoint struct so we can be stored in the listener
        /// when the listener calls the fascade, onRequest will have
        /// access to all of us via fieldParentPtr
        pub fn getEndpoint(self: *Self) *zap.SimpleEndpoint {
            return &self.fascade;
        }

        pub fn addEndpoint(self: *Self, ep: *zap.SimpleEndpoint) !void {
            for (self.endpoints.items) |other| {
                std.debug.print("middleware: comparing {s} with {s}\n", .{ ep.settings.path, other.settings.path });
                if (std.mem.startsWith(
                    u8,
                    other.settings.path,
                    ep.settings.path,
                ) or std.mem.startsWith(
                    u8,
                    ep.settings.path,
                    other.settings.path,
                )) {
                    return zap.EndpointListenerError.EndpointPathShadowError;
                }
            }
            std.debug.print("middleware: adding endpoint {s}\n", .{ep.settings.path});
            try self.endpoints.append(ep);
        }

        fn _internal_handleRequest(self: *Self, r: zap.SimpleRequest) void {
            std.debug.print("middleware.handling\n", .{});
            switch (self.authenticator.authenticateRequest(&r)) {
                .AuthOK => {
                    std.debug.print("middleware.authenticated\n", .{});
                    if (r.isFinished()) {
                        std.debug.print("middleware: already processed\n", .{});
                        return;
                    }
                    if (r.path) |p| {
                        for (self.endpoints.items) |ep| {
                            if (std.mem.startsWith(u8, p, ep.settings.path)) {
                                std.debug.print("middleware.auth: dispatch to endpoint {s}\n", .{ep.settings.path});
                                if (r.method) |m| {
                                    if (std.mem.eql(u8, m, "GET")) {
                                        const h = ep.settings.get orelse break;
                                        return h(ep, r);
                                    } else if (std.mem.eql(u8, m, "POST")) {
                                        const h = ep.settings.post orelse break;
                                        return h(ep, r);
                                    } else if (std.mem.eql(u8, m, "PUT")) {
                                        const h = ep.settings.put orelse break;
                                        return h(ep, r);
                                    } else if (std.mem.eql(u8, m, "DELETE")) {
                                        const h = ep.settings.delete orelse break;
                                        return h(ep, r);
                                    } else if (std.mem.eql(u8, m, "PATCH")) {
                                        const h = ep.settings.patch orelse break;
                                        return h(ep, r);
                                    }
                                }
                                break;
                            }
                        }
                        std.debug.print("middleware.auth: dispatch to router {s}\n", .{p});
                        var c = self.authenticator.getContext(&r);
                        self.router.dispatch(r, c);
                    }
                },
                .Handled => {
                    std.debug.print("middleware.handled\n", .{});
                    if (r.isFinished()) {
                        std.debug.print("middleware: already processed\n", .{});
                        return;
                    }
                    if (r.path) |p| {
                        for (self.endpoints.items) |ep| {
                            if (std.mem.startsWith(u8, p, ep.settings.path)) {
                                std.debug.print("middleware.auth: dispatch to endpoint {s}\n", .{ep.settings.path});
                                if (r.method) |m| {
                                    std.debug.print("middleware.auth: method {s}\n", .{m});
                                    if (std.mem.eql(u8, m, "GET")) {
                                        const h = ep.settings.get orelse break;
                                        return h(ep, r);
                                    } else if (std.mem.eql(u8, m, "POST")) {
                                        const h = ep.settings.post orelse break;
                                        return h(ep, r);
                                    } else if (std.mem.eql(u8, m, "PUT")) {
                                        const h = ep.settings.put orelse break;
                                        return h(ep, r);
                                    } else if (std.mem.eql(u8, m, "DELETE")) {
                                        const h = ep.settings.delete orelse break;
                                        return h(ep, r);
                                    } else if (std.mem.eql(u8, m, "PATCH")) {
                                        const h = ep.settings.patch orelse break;
                                        return h(ep, r);
                                    }
                                }
                                break;
                            }
                        }
                        std.debug.print("middleware.handled: dispatch to no-context router {s}\n", .{p});
                        self.router.dispatch(r, null);
                    }
                },
                .AuthFailed => unreachable,
            }
        }

        /// here, the fascade will be passed in
        pub fn handleRequest(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            _internal_handleRequest(myself, r);
        }
    };
}
