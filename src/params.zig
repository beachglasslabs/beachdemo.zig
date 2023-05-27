// https://github.com/nektro/zig-UrlValues

const std = @import("std");

pub const Self = @This();

inner: std.StringArrayHashMap([]const u8),

pub fn init(alloc: std.mem.Allocator) Self {
    return .{
        .inner = std.StringArrayHashMap([]const u8).init(alloc),
    };
}

pub fn deinit(self: *Self) void {
    self.inner.deinit();
}

pub fn initFromString(alloc: std.mem.Allocator, input: []const u8) !Self {
    var uv = Self.init(alloc);
    var iter = std.mem.split(u8, input, "&");
    while (iter.next()) |piece| {
        if (piece.len == 0) continue;
        var jter = std.mem.split(u8, piece, "=");
        try uv.add(jter.next().?, jter.rest());
    }
    return uv;
}

pub fn add(self: *Self, key: []const u8, value: []const u8) !void {
    try self.inner.putNoClobber(key, value);
}

pub fn get(self: *Self, key: []const u8) ?[]const u8 {
    return self.inner.get(key);
}

pub fn take(self: *Self, key: []const u8) ?[]const u8 {
    const kv = self.inner.fetchOrderedRemove(key);
    if (kv == null) return null;
    return kv.?.value;
}

pub fn encode(self: Self) ![]const u8 {
    const alloc = self.inner.allocator;
    var list = std.ArrayList(u8).init(alloc);
    defer list.deinit();
    var iter = self.inner.iterator();
    var i: usize = 0;
    while (iter.next()) |entry| : (i += 1) {
        if (i > 0) try list.writer().writeAll("&");
        if (std.mem.eql(u8, entry.key_ptr.*, "code")) {
            try list.writer().print("{s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* });
        } else {
            const value = try std.Uri.escapeString(alloc, entry.value_ptr.*);
            defer alloc.free(value);
            try list.writer().print("{s}={s}", .{ entry.key_ptr.*, value });
        }
    }
    return list.toOwnedSlice();
}
