const std = @import("std");
const zap = @import("zap");
const Endpoint = @import("user_endpoint.zig");

const Method = enum {
    DELETE,
    GET,
    PATCH,
    POST,
    PUT,
};

const DispatchHttpRequestFn = *const fn (std.mem.Allocator, zap.SimpleRequest) anyerror!void;

fn setupRoutes(a: std.mem.Allocator) !void {
    routes = std.StringHashMap(DispatchHttpRequestFn).init(a);
    try routes.put("/auth", auth);
    try routes.put("/", index);
}

var routes: std.StringHashMap(DispatchHttpRequestFn) = undefined;

var gpa = std.heap.GeneralPurposeAllocator(.{
    .thread_safe = true,
}){};
var allocator = gpa.allocator();

fn dispatchRoutes(r: zap.SimpleRequest) void {
    std.debug.print("in dispatch:\n", .{});
    if (r.query) |query| {
        std.debug.print("QUERY: {s}\n", .{query});
    }

    if (r.path) |path| {
        std.debug.print("PATH: {s}\n", .{path});
        if (routes.get(path)) |handler| {
            handler(allocator, r) catch |err| {
                const error_html = std.fmt.allocPrint(allocator, "<html><body><pre>{}</pre></body></html>", .{err}) catch return;
                defer allocator.free(error_html);
                r.sendBody(error_html) catch return;
            };
            return;
        }
    }

    r.sendBody("<html><body><h1>Oops!</h1></body></html>") catch return;
}

fn auth(a: std.mem.Allocator, r: zap.SimpleRequest) !void {
    return render(a, r, "web/templates/auth.html", .{});
}

fn index(a: std.mem.Allocator, r: zap.SimpleRequest) !void {
    return render(a, r, "web/templates/index.html", .{});
}

fn render(a: std.mem.Allocator, r: zap.SimpleRequest, t: []const u8, m: anytype) !void {
    const file = try std.fs.cwd().openFile(
        t,
        .{},
    );
    defer file.close();

    const size = (try file.stat()).size;

    const template = try file.reader().readAllAlloc(a, size);

    const p = try zap.MustacheNew(template);
    defer zap.MustacheFree(p);
    const ret = zap.MustacheBuild(p, m);
    defer ret.deinit();
    if (r.setContentType(.HTML)) {
        if (ret.str()) |resp| {
            try r.sendBody(resp);
        } else {
            try r.sendBody("<html><body><h1>MustacheBuild() failed!</h1></body></html>");
        }
    } else |err| return err;
    return;
}

pub fn main() !void {
    // setup routes
    try setupRoutes(allocator);

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
