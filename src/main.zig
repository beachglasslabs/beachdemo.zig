const std = @import("std");
const zap = @import("zap");
const Endpoint = @import("user_endpoint.zig");

fn dispatchRoutes(r: zap.SimpleRequest) void {
    std.debug.print("in dispatch:\n", .{});
    if (r.query) |the_query| {
        std.debug.print("QUERY: {s}\n", .{the_query});
    }

    if (r.path) |the_path| {
        std.debug.print("PATH: {s}\n", .{the_path});

        if (std.mem.eql(u8, the_path, "/auth")) {
            var gpa = std.heap.GeneralPurposeAllocator(.{
                .thread_safe = true,
            }){};
            const allocator = gpa.allocator();

            const file = std.fs.cwd().openFile(
                "web/templates/auth.html",
                .{},
            ) catch |err| {
                std.debug.print("Error opening template: {}\n", .{err});
                return;
            };
            defer file.close();

            const stat = file.stat() catch |err| {
                std.debug.print("Error getting template file size: {}\n", .{err});
                return;
            };

            const template = file.reader().readAllAlloc(allocator, stat.size) catch |err| {
                std.debug.print("Error reading template: {}\n", .{err});
                return;
            };
            const p = zap.MustacheNew(template) catch return;
            defer zap.MustacheFree(p);
            const ret = zap.MustacheBuild(p, .{
                .name = "Test",
            });
            defer ret.deinit();
            if (r.setContentType(.HTML)) {
                if (ret.str()) |s| {
                    r.sendBody(s) catch return;
                } else {
                    r.sendBody("<html><body><h1>MustacheBuild() failed!</h1></body></html>") catch return;
                }
            } else |err| {
                std.debug.print("Error while setting content type: {}\n", .{err});
            }
        }
    }

    r.sendBody("<html><body><h1>Oops!</h1></body></html>") catch return;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .thread_safe = true,
    }){};
    var allocator = gpa.allocator();

    //try setupRoutes(allocator);

    //var listener = zap.SimpleHttpListener.init(.{
    //    .port = 3000,
    //    .on_request = dispatchRoutes,
    //    .public_folder = "public",
    //    .log = true,
    //    .max_clients = 100000,
    //});

    // setup listener
    var listener = zap.SimpleEndpointListener.init(
        allocator,
        .{
            .port = 3000,
            .on_request = dispatchRoutes,
            .public_folder = "public",
            .log = true,
            .max_clients = 100000,
            .max_body_size = 100 * 1024 * 1024,
        },
    );
    defer listener.deinit();

    var user_endpoint = Endpoint.init(allocator, "/users");
    defer user_endpoint.deinit();

    var session_endpoint = Endpoint.init(allocator, "/sessions");
    session_endpoint.deinit();

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
