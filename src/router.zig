const std = @import("std");
const zap = @import("zap");

var alloc: std.mem.Allocator = undefined;
var gets: std.StringHashMap(zap.SimpleHttpRequestFn) = undefined;
var puts: std.StringHashMap(zap.SimpleHttpRequestFn) = undefined;
var posts: std.StringHashMap(zap.SimpleHttpRequestFn) = undefined;
var deletes: std.StringHashMap(zap.SimpleHttpRequestFn) = undefined;
var patches: std.StringHashMap(zap.SimpleHttpRequestFn) = undefined;

pub fn init(a: std.mem.Allocator) void {
    alloc = a;
    gets = std.StringHashMap(zap.SimpleHttpRequestFn).init(a);
    posts = std.StringHashMap(zap.SimpleHttpRequestFn).init(a);
    puts = std.StringHashMap(zap.SimpleHttpRequestFn).init(a);
    deletes = std.StringHashMap(zap.SimpleHttpRequestFn).init(a);
    patches = std.StringHashMap(zap.SimpleHttpRequestFn).init(a);
}

pub fn deinit() void {
    gets.deinit();
    posts.deinit();
    puts.deinit();
    deletes.deinit();
    patches.deinit();
}

pub fn get(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try gets.put(path, handler);
}

pub fn put(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try puts.put(path, handler);
}

pub fn post(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try posts.put(path, handler);
}

pub fn delete(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try deletes.put(path, handler);
}

pub fn patch(path: []const u8, handler: zap.SimpleHttpRequestFn) !void {
    try patches.put(path, handler);
}

pub fn dispatcher(r: zap.SimpleRequest) void {
    std.debug.print("in dispatch:\n", .{});
    if (r.query) |query| {
        std.debug.print("QUERY: {s}\n", .{query});
    }

    if (r.path) |path| {
        std.debug.print("PATH: {s}\n", .{path});
        if (r.method) |method| {
            if (std.mem.eql(u8, method, "GET")) {
                if (gets.get(path)) |handler| {
                    return handler(r);
                }
            } else if (std.mem.eql(u8, method, "POST")) {
                if (posts.get(path)) |handler| {
                    return handler(r);
                }
            } else if (std.mem.eql(u8, method, "PUT")) {
                if (puts.get(path)) |handler| {
                    return handler(r);
                }
            } else if (std.mem.eql(u8, method, "DELETE")) {
                if (deletes.get(path)) |handler| {
                    return handler(r);
                }
            } else if (std.mem.eql(u8, method, "PATCH")) {
                if (patches.get(path)) |handler| {
                    return handler(r);
                }
            }
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
