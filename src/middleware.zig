const std = @import("std");
const zap = @import("zap");

/// Wrap multiple endpoints
pub fn Middleware(comptime Router: type, comptime Authenticator: type, comptime ContextType: type) type {
    return struct {
        endpoints: std.ArrayList(*zap.SimpleEndpoint),
        authenticator: *Authenticator,
        router: *Router,
        fascade: zap.SimpleEndpoint,

        pub const ContextRequestFn = *const fn (*Router, zap.SimpleRequest, *ContextType) void;
        pub const RequestFn = *const fn (*zap.SimpleEndpoint, zap.SimpleRequest) void;
        const Self = @This();

        pub fn init(a: std.mem.Allocator, router: *Router, authenticator: *Authenticator) Self {
            return .{
                .authenticator = authenticator,
                .endpoints = std.ArrayList(*zap.SimpleEndpoint).init(a),
                .router = router,
                .fascade = zap.SimpleEndpoint.init(.{
                    .path = "/", // we do everything
                    .get = get,
                    .post = post,
                    .put = put,
                    .delete = delete,
                    .patch = patch,
                }),
            };
        }

        pub fn deinit(self: *Self) void {
            self.endpoints.deinit();
            self.fascade.deinit();
        }

        /// get the mega endpoint struct so we can be stored in the listener
        /// when the listener calls the fascade, onRequest will have
        /// access to all of us via fieldParentPtr
        pub fn getEndpoint(self: *Self) *zap.SimpleEndpoint {
            return &self.fascade;
        }

        pub fn addEndpoint(self: *Self, ep: *zap.SimpleEndpoint) !void {
            for (self.endpoints.items) |other| {
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
            try self.endpoints.append(ep);
        }

        fn _internal_handleRequest(self: *Self, r: zap.SimpleRequest, handler: ?RequestFn) void {
            if (self.authenticator.authenticateRequest(&r) == .AuthOK) {
                std.debug.print("middleware: authenticated\n", .{});
                if (r.path) |p| {
                    std.debug.print("middleware: internal handler for {s}\n", .{p});
                    for (self.endpoints.items) |ep| {
                        if (std.mem.startsWith(u8, p, ep.settings.path)) {
                            std.debug.print("middleware: dispatch to endpoint {s}\n", .{ep.settings.path});
                            handler.?(ep, r);
                            return;
                        }
                    }
                    std.debug.print("middleware: dispatch to router {s}\n", .{p});
                    return self.router.dispatch(r, null);
                }
            }
        }

        /// here, the fascade will be passed in
        pub fn get(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            std.debug.print("middleware.get\n", .{});
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            _internal_handleRequest(myself, r, e.settings.get);
        }

        /// here, the fascade will be passed in
        pub fn post(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            std.debug.print("middleware.post\n", .{});
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            _internal_handleRequest(myself, r, e.settings.post);
        }

        /// here, the fascade will be passed in
        pub fn put(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            std.debug.print("middleware.put\n", .{});
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            _internal_handleRequest(myself, r, e.settings.put);
        }

        /// here, the fascade will be passed in
        pub fn delete(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            std.debug.print("middleware.delete\n", .{});
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            _internal_handleRequest(myself, r, e.settings.delete);
        }

        /// here, the fascade will be passed in
        pub fn patch(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            std.debug.print("middleware.patch\n", .{});
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            _internal_handleRequest(myself, r, e.settings.patch);
        }
    };
}
