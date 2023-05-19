const std = @import("std");
const zap = @import("zap");
const UserEndpoint = @import("user_endpoint.zig");
const SessionEndpoint = @import("session_endpoint.zig");
const Router = @import("router.zig");
const Middleware = @import("middleware.zig");
const UserSession = @import("auth.zig");
const Users = @import("users.zig");
const Sessions = @import("sessions.zig");
const User = Users.User;
const Session = Sessions.Session;

fn auth(r: zap.SimpleRequest) void {
    Router.renderTemplate(r, "web/templates/auth.html", .{}) catch return;
}

fn index(r: zap.SimpleRequest) void {
    Router.renderTemplate(r, "web/templates/index.html", .{}) catch return;
}

fn redirect(r: zap.SimpleRequest) void {
    r.redirectTo("/auth", zap.StatusCode.see_other) catch return;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .thread_safe = true,
    }){};
    var allocator = gpa.allocator();

    // setup routes
    Router.init(allocator);
    defer Router.deinit();

    try Router.get("/auth", auth);
    try Router.get("/", index);

    // setup listener
    var listener = zap.SimpleEndpointListener.init(
        allocator,
        .{
            .on_request = null,
            .port = 3000,
            .public_folder = "public",
            .log = true,
            .max_clients = 100000,
            .max_body_size = 100 * 1024 * 1024,
        },
    );
    defer listener.deinit();

    var user_endpoint = UserEndpoint.init(allocator, "/users");
    defer user_endpoint.deinit();

    var session_endpoint = SessionEndpoint.init(allocator, "/session", &user_endpoint.users);
    defer session_endpoint.deinit();

    // create authenticator
    const Authenticator = UserSession.SessionAuth(User, Session);
    const auth_args = UserSession.SessionAuthArgs{
        .username_param = "email",
        .password_param = "password",
        .auth_page = "/auth",
        .white_list = &[_][]const u8{ "/users", "/session", "/auth" },
        .cookie_name = "token",
        .cookie_maxage = 3,
        .redirect_code = zap.StatusCode.see_other,
    };
    var authenticator = try Authenticator.init(allocator, &user_endpoint.users.users_by_email, &session_endpoint.sessions.sessions, auth_args);
    defer authenticator.deinit();

    // create authenticating endpoint
    const AuthMiddleware = Middleware.Middleware(Authenticator);
    var auth_wrapper = AuthMiddleware.init(allocator, Router.dispatcher, &authenticator, redirect);
    try auth_wrapper.addEndpoint(user_endpoint.getEndpoint());
    try auth_wrapper.addEndpoint(session_endpoint.getEndpoint());

    // add endpoints
    try listener.addEndpoint(auth_wrapper.getEndpoint());

    // listen
    try listener.listen();

    std.debug.print("Listening on 0.0.0.0:3000\n", .{});

    // start worker threads
    zap.start(.{
        .threads = 100,
        // IMPORTANT! It is crucial to only have a single worker for this example to work!
        // Multiple workers would have multiple copies of the users hashmap.
        //
        // Since zap is quite fast, you can do A LOT with a single worker.
        // Try it with `zig build run-endpoint -Drelease-fast`
        .workers = 1,
    });
}
