const std = @import("std");
const zap = @import("zap");

allocator: std.mem.Allocator = undefined,

pub const Self = @This();

pub fn init(allocator: std.mem.Allocator) Self {
    return .{
        .allocator = allocator,
    };
}

pub fn deinit(_: *Self) void {}

pub fn render(self: *Self, r: zap.SimpleRequest, t: []const u8, m: anytype) !void {
    const file = try std.fs.cwd().openFile(
        t,
        .{},
    );
    defer file.close();

    const size = (try file.stat()).size;

    const template = try file.reader().readAllAlloc(self.allocator, size);
    defer self.allocator.free(template);

    const p = try zap.MustacheNew(template);
    defer zap.MustacheFree(p);
    const ret = zap.MustacheBuild(p, m);
    defer ret.deinit();
    if (r.setContentType(.HTML)) {
        if (ret.str()) |resp| {
            r.setStatus(zap.StatusCode.ok);
            try r.sendBody(resp);
        } else {
            r.setStatus(zap.StatusCode.not_found);
            try r.sendBody("");
        }
    } else |err| return err;
    return;
}
