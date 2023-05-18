const std = @import("std");
const zap = @import("zap");

/// Wrap multiple endpoints
pub fn Middleware(comptime Authenticator: type) type {
    return struct {
        allocator: std.mem.Allocator,
        authenticator: *Authenticator,
        endpoints: std.ArrayList(*zap.SimpleEndpoint),
        fascade: zap.SimpleEndpoint,
        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, authenticator: *Authenticator) Self {
            return .{
                .allocator = allocator,
                .authenticator = authenticator,
                .endpoints = std.ArrayList(*zap.SimpleEndpoint).init(),
                .fascade = zap.SimpleEndpoint.init(.{
                    .path = "/", // we do everything
                    // we override only the set ones. the other ones
                    // are set to null anyway -> will be nopped out
                    .get = get,
                    .post = post,
                    .put = put,
                    .delete = delete,
                    .patch = patch,
                    .unauthorized = default_unauth,
                }),
            };
        }

        /// get the mega endpoint struct so we can be stored in the listener
        /// when the listener calls the fascade, onRequest will have
        /// access to all of us via fieldParentPtr
        pub fn getEndpoint(self: *Self) *zap.SimpleEndpoint {
            return &self.fascade;
        }

        pub fn default_unauth(r: zap.SimpleRequest) void {
            r.setStatus(zap.unauthorized);
        }

        pub fn addEndpoint(self: *Self, e: *zap.SimpleEndpoint) void {
            self.endpoints.append(e);
        }

        /// here, the fascade will be passed in
        pub fn get(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(myself.endpoint, r);
                        return;
                    } else {
                        r.setStatus(.unauthorized);
                        r.sendBody("UNAUTHORIZED") catch return;
                        return;
                    }
                },
                .AuthOK => myself.endpoint.settings.get.?(myself.endpoint, r),
                .Handled => {},
            }
        }

        /// here, the fascade will be passed in
        pub fn post(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(myself.endpoint, r);
                        return;
                    } else {
                        r.setStatus(.unauthorized);
                        r.sendBody("UNAUTHORIZED") catch return;
                        return;
                    }
                },
                .AuthOK => myself.endpoint.settings.post.?(myself.endpoint, r),
                .Handled => {},
            }
        }

        /// here, the fascade will be passed in
        pub fn put(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(myself.endpoint, r);
                        return;
                    } else {
                        r.setStatus(.unauthorized);
                        r.sendBody("UNAUTHORIZED") catch return;
                        return;
                    }
                },
                .AuthOK => myself.endpoint.settings.put.?(myself.endpoint, r),
                .Handled => {},
            }
        }

        /// here, the fascade will be passed in
        pub fn delete(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(myself.endpoint, r);
                        return;
                    } else {
                        r.setStatus(.unauthorized);
                        r.sendBody("UNAUTHORIZED") catch return;
                        return;
                    }
                },
                .AuthOK => myself.endpoint.settings.delete.?(myself.endpoint, r),
                .Handled => {},
            }
        }

        /// here, the fascade will be passed in
        pub fn patch(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
            const myself: *Self = @fieldParentPtr(Self, "fascade", e);
            switch (myself.authenticator.authenticateRequest(&r)) {
                .AuthFailed => {
                    if (e.settings.unauthorized) |unauthorized| {
                        unauthorized(myself.endpoint, r);
                        return;
                    } else {
                        r.setStatus(.unauthorized);
                        r.sendBody("UNAUTHORIZED") catch return;
                        return;
                    }
                },
                .AuthOK => myself.endpoint.settings.patch.?(myself.endpoint, r),
                .Handled => {},
            }
        }
    };
}
