const std = @import("std");
const zap = @import("zap");

var alloc: std.mem.Allocator = undefined;
var routes: std.StringHashMap(zap.SimpleHttpRequestFn) = undefined;

pub fn init(a: std.mem.Allocator) void {
    alloc = a;
    routes = std.StringHashMap(zap.SimpleHttpRequestFn).init(a);
}

pub fn deinit() void {
    routes.deinit();
}

// TODO route based on method too
pub fn get(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try routes.put(path, handler);
}

pub fn put(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try get(path, handler);
}

pub fn post(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try get(path, handler);
}

pub fn delete(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try get(path, handler);
}

pub fn patch(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try get(path, handler);
}

pub fn dispatcher(r: zap.SimpleRequest) void {
    std.debug.print("in dispatch:\n", .{});
    if (r.query) |query| {
        std.debug.print("QUERY: {s}\n", .{query});
    }

    if (r.path) |path| {
        std.debug.print("PATH: {s}\n", .{path});
        if (routes.get(path)) |handler| {
            return handler(r);
        }
    }

    r.setStatus(zap.StatusCode.not_found);
    r.sendBody("<html><body><h1>Oops!</h1></body></html>") catch return;
}

pub fn renderTemplate(r: zap.SimpleRequest, t: []const u8, m: anytype) !void {
    const file = try std.fs.cwd().openFile(
        t,
        .{},
    );
    defer file.close();

    const size = (try file.stat()).size;

    const template = try file.reader().readAllAlloc(alloc, size);

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
