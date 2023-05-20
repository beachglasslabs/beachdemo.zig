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

fn auth(router: *Router.Router(User), r: zap.SimpleRequest, _: ?*User) void {
    router.renderTemplate(r, "web/templates/auth.html", .{}) catch return;
}

fn index(router: *Router.Router(User), r: zap.SimpleRequest, _: ?*User) void {
    router.renderTemplate(r, "web/templates/index.html", .{ .name = "hello", .avatar = "/img/default-red.png" }) catch return;
}

fn profiles(router: *Router.Router(User), r: zap.SimpleRequest, _: ?*User) void {
    router.renderTemplate(r, "web/templates/profiles.html", .{ .name = "hello", .avatar = "/img/default-blue.png" }) catch return;
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
    var router = try Router.Router(User).init(allocator, "/auth");
    defer router.deinit();

    try router.get("/", index);
    try router.get("/auth", auth);
    try router.get("/profiles", profiles);

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

    var session_endpoint = SessionEndpoint.init(allocator, "/sessions", &user_endpoint.users);
    defer session_endpoint.deinit();

    // create authenticator
    const Authenticator = UserSession.SessionAuth(Users, Sessions);
    const auth_args = UserSession.SessionAuthArgs{
        .name_param = "name",
        .subject_param = "email",
        .password_param = "password",
        .signin_url = "/auth",
        .signup_url = "/auth",
        .success_url = "/profiles",
        .signin_callback = "/sessions",
        .signup_callback = "/users",
        .cookie_name = "token",
        .cookie_maxage = 1337,
        .redirect_code = zap.StatusCode.see_other,
    };
    var authenticator = try Authenticator.init(allocator, &user_endpoint.users, &session_endpoint.sessions, auth_args);
    defer authenticator.deinit();

    // create authenticating endpoint
    const AuthMiddleware = Middleware.Middleware(Router.Router(User), Authenticator, zap.AuthResult);
    var auth_wrapper = AuthMiddleware.init(allocator, &router, &authenticator);
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
