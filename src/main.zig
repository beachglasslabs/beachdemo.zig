const std = @import("std");
const zap = @import("zap");
const UserEndpoint = @import("user_endpoint.zig");
const SessionEndpoint = @import("session_endpoint.zig");
const Router = @import("router.zig");

fn auth(r: zap.SimpleRequest) void {
    Router.renderTemplate(r, "web/templates/auth.html", .{}) catch return;
}

fn index(r: zap.SimpleRequest) void {
    Router.renderTemplate(r, "web/templates/index.html", .{}) catch return;
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
            .port = 3000,
            .on_request = Router.dispatcher,
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

    // add endpoints
    try listener.addEndpoint(user_endpoint.getEndpoint());
    try listener.addEndpoint(session_endpoint.getEndpoint());

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
