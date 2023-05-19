const std = @import("std");
const zap = @import("zap");

/// Wrap multiple endpoints
pub fn Middleware(comptime Authenticator: type) type {
    return struct {
        endpoints: std.ArrayList(*zap.SimpleEndpoint),
        authenticator: *Authenticator,
        handler: zap.SimpleHttpRequestFn,
        redirect: zap.SimpleHttpRequestFn,
        fascade: zap.SimpleEndpoint,
        const Self = @This();

        pub fn init(a: std.mem.Allocator, handler: zap.SimpleHttpRequestFn, authenticator: *Authenticator, redirect: zap.SimpleHttpRequestFn) Self {
            return .{
                .authenticator = authenticator,
                .endpoints = std.ArrayList(*zap.SimpleEndpoint).init(a),
                .handler = handler,
                .redirect = redirect,
                .fascade = zap.SimpleEndpoint.init(.{
                    .path = "/", // we do everything
                    .get = get,
                    .post = post,
                    .put = put,
                    .delete = delete,
                    .patch = patch,
                    .unauthorized = redirectTo,
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

        pub fn redirectTo(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            return myself.redirect(r);
        }

        /// here, the fascade will be passed in
        pub fn get(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            std.debug.print("in wrapper.get\n", .{});
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(&myself.fascade, r);
                        return;
                    } else {
                        myself.redirect(r);
                        return;
                    }
                },
                .AuthOK => {
                    std.debug.print("in wrapper.get: auth ok\n", .{});
                    if (r.path) |p| {
                        std.debug.print("in wrapper.get: {s}\n", .{p});
                        var handled = false;
                        for (myself.endpoints.items) |ep| {
                            if (std.mem.startsWith(u8, p, ep.settings.path)) {
                                handled = true;
                                std.debug.print("in wrapper.get: passing to endpoint {s}\n", .{ep.settings.path});
                                ep.settings.get.?(ep, r);
                                return;
                            }
                        }
                        if (!handled) {
                            std.debug.print("in wrapper.get: passing to handler\n", .{});
                            myself.handler(r);
                        }
                    }
                },
                .Handled => {},
            }
        }

        /// here, the fascade will be passed in
        pub fn post(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(&myself.fascade, r);
                        return;
                    } else {
                        myself.redirect(r);
                        return;
                    }
                },
                .AuthOK => {
                    if (r.path) |p| {
                        var handled = false;
                        for (myself.endpoints.items) |ep| {
                            if (std.mem.startsWith(u8, p, ep.settings.path)) {
                                handled = true;
                                ep.settings.post.?(ep, r);
                                return;
                            }
                        }
                        if (!handled) {
                            myself.handler(r);
                        }
                    }
                },
                .Handled => {},
            }
        }

        /// here, the fascade will be passed in
        pub fn put(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(&myself.fascade, r);
                        return;
                    } else {
                        myself.redirect(r);
                        return;
                    }
                },
                .AuthOK => {
                    if (r.path) |p| {
                        var handled = false;
                        for (myself.endpoints.items) |ep| {
                            if (std.mem.startsWith(u8, p, ep.settings.path)) {
                                handled = true;
                                ep.settings.put.?(ep, r);
                                return;
                            }
                        }
                        if (!handled) {
                            myself.handler(r);
                        }
                    }
                },
                .Handled => {},
            }
        }

        /// here, the fascade will be passed in
        pub fn delete(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(&myself.fascade, r);
                        return;
                    } else {
                        myself.redirect(r);
                        return;
                    }
                },
                .AuthOK => {
                    if (r.path) |p| {
                        var handled = false;
                        for (myself.endpoints.items) |ep| {
                            if (std.mem.startsWith(u8, p, ep.settings.path)) {
                                handled = true;
                                ep.settings.delete.?(ep, r);
                                return;
                            }
                        }
                        if (!handled) {
                            myself.handler(r);
                        }
                    }
                },
                .Handled => {},
            }
        }

        /// here, the fascade will be passed in
        pub fn patch(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(&myself.fascade, r);
                        return;
                    } else {
                        myself.redirect(r);
                        return;
                    }
                },
                .AuthOK => {
                    if (r.path) |p| {
                        var handled = false;
                        for (myself.endpoints.items) |ep| {
                            if (std.mem.startsWith(u8, p, ep.settings.path)) {
                                handled = true;
                                ep.settings.patch.?(ep, r);
                                return;
                            }
                        }
                        if (!handled) {
                            myself.handler(r);
                        }
                    }
                },
                .Handled => {},
            }
        }
    };
}
