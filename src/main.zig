const std = @import("std");
const zap = @import("zap");
const UserEndpoint = @import("user_endpoint.zig");
const SessionEndpoint = @import("session_endpoint.zig");
const MovieEndpoint = @import("movie_endpoint.zig");
const Router = @import("router.zig");
const EndpointRouter = @import("endpoint_router.zig");
const SessionManager = @import("session_manager.zig");
const User = @import("users.zig").User;

fn index(router: *Router.Router(User), r: zap.SimpleRequest, maybe_user: ?User) void {
    if (maybe_user) |user| {
        std.debug.print("index: user is {s}\n", .{user.name});
        router.renderTemplate(r, "web/templates/index.html", .{ .name = user.name, .avatar = user.avatar }) catch return;
    } else {
        std.debug.print("index: user is null\n", .{});
    }
}

fn profiles(router: *Router.Router(User), r: zap.SimpleRequest, maybe_user: ?User) void {
    if (maybe_user) |user| {
        std.debug.print("profiles: user is {s}\n", .{user.name});
        router.renderTemplate(r, "web/templates/profiles.html", .{ .name = user.name, .avatar = user.avatar }) catch return;
    } else {
        std.debug.print("profiles: user is null\n", .{});
    }
}

fn redirect(r: zap.SimpleRequest) void {
    r.redirectTo("/sessions", zap.StatusCode.see_other) catch return;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .thread_safe = true,
    }){};

    {
        var allocator = gpa.allocator();

        // setup routes
        var router = try Router.Router(User).init(allocator);
        defer router.deinit();

        try router.get("/", index);
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

        var session_endpoint = SessionEndpoint.init(allocator, "/sessions");
        defer session_endpoint.deinit();

        var movie_endpoint = try MovieEndpoint.init(allocator, "/movies", "web/movies.json");
        defer movie_endpoint.deinit();

        var movies = movie_endpoint.movies.movies;
        var iter = movies.valueIterator();
        while (iter.next()) |m| {
            std.debug.print("got movie {s}\n", .{m.title});
        }

        // create authenticator
        const Authenticator = SessionManager.Authenticator(UserEndpoint, SessionEndpoint, User);
        const auth_settings = SessionManager.AuthenticatorSettings{
            .name_param = "name",
            .subject_param = "email",
            .password_param = "password",
            .signin_url = "/sessions",
            .signup_url = "/sessions",
            .success_url = "/profiles",
            .signin_callback = "/sessions",
            .signup_callback = "/users",
            .cookie_name = "token",
            .cookie_maxage = 1337,
            .redirect_code = zap.StatusCode.see_other,
        };
        var authenticator = try Authenticator.init(allocator, &user_endpoint, &session_endpoint, auth_settings);
        defer authenticator.deinit();

        // create authenticating endpoint
        const MainRouter = EndpointRouter.EndpointRouter(Router.Router(User), Authenticator);
        var dispatcher = MainRouter.init(allocator, &router, &authenticator);
        defer dispatcher.deinit();

        // add endpoints
        try dispatcher.addEndpoint(user_endpoint.getEndpoint());
        try dispatcher.addEndpoint(session_endpoint.getEndpoint());
        try dispatcher.addEndpoint(movie_endpoint.getEndpoint());
        try listener.addEndpoint(dispatcher.getEndpoint());

        // listen
        try listener.listen();

        std.debug.print("Listening on 0.0.0.0:3000\n", .{});

        // start worker threads
        zap.start(.{
            .threads = 1,
            // IMPORTANT! It is crucial to only have a single worker for this example to work!
            // Multiple workers would have multiple copies of the users hashmap.
            //
            // Since zap is quite fast, you can do A LOT with a single worker.
            // Try it with `zig build run-endpoint -Drelease-fast`
            .workers = 1,
        });
    }

    // all defers should have run by now
    std.debug.print("\n\nSTOPPED!\n\n", .{});
    // we'll arrive here after zap.stop()
    const leaked = gpa.detectLeaks();
    std.debug.print("Leaks detected: {}\n", .{leaked});
}
