const std = @import("std");
const zap = @import("zap");
const Movies = @import("movies.zig");
const Movie = Movies.Movie;

// an Endpoint

pub const Self = @This();

allocator: std.mem.Allocator = undefined,
endpoint: zap.SimpleEndpoint = undefined,
movies: Movies = undefined,

pub fn init(
    a: std.mem.Allocator,
    movie_path: []const u8,
    data_path: []const u8,
) !Self {
    return .{
        .allocator = a,
        .movies = try Movies.init(a, data_path),
        .endpoint = zap.SimpleEndpoint.init(.{
            .path = movie_path,
            .get = getMovie,
        }),
    };
}

pub fn deinit(self: *Self) void {
    self.movies.deinit();
}

pub fn getMovies(self: *Self) *Movies {
    return &self.movies;
}

pub fn getEndpoint(self: *Self) *zap.SimpleEndpoint {
    return &self.endpoint;
}

fn movieIdFromPath(self: *Self, path: []const u8) ?[]const u8 {
    if (path.len >= self.endpoint.settings.path.len + 2) {
        if (path[self.endpoint.settings.path.len] != '/') {
            return null;
        }
        return path[self.endpoint.settings.path.len + 1 ..];
    }
    return null;
}

fn getMovie(e: *zap.SimpleEndpoint, r: zap.SimpleRequest) void {
    const self = @fieldParentPtr(Self, "endpoint", e);
    if (r.path) |path| {
        // /movies
        if (path.len == e.settings.path.len) {
            return self.listMovies(r);
        }
        var jsonbuf: [256]u8 = undefined;
        if (self.movieIdFromPath(path)) |id| {
            if (self.movies.get(id)) |movie| {
                if (zap.stringifyBuf(&jsonbuf, movie, .{})) |json| {
                    r.sendJson(json) catch return;
                }
            }
        }
    }
}

fn listMovies(self: *Self, r: zap.SimpleRequest) void {
    if (self.movies.toJSON()) |json| {
        defer self.allocator.free(json);
        r.sendJson(json) catch return;
    } else |err| {
        std.debug.print("LIST error: {}\n", .{err});
    }
}
