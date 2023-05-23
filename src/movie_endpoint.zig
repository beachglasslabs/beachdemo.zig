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
        if (path.len == self.endpoint.settings.path.len) {
            std.debug.print("movie endpoint.get: all movies\n", .{});
            return self.listMovies(r);
        }
        if (self.movieIdFromPath(path)) |id| {
            std.debug.print("movie endpoint.get: looking for {s}\n", .{id});
            if (std.mem.eql(u8, id, "random")) {
                if (self.movies.random()) |movie| {
                    std.debug.print("movie endpoint.get: found random movie {s}\n", .{movie.title});
                    const json = std.json.stringifyAlloc(self.allocator, movie, .{}) catch return;
                    defer self.allocator.free(json);
                    std.debug.print("movie endpoint.get: {s}\n", .{json});
                    r.sendJson(json) catch return;
                    return;
                }
            } else if (self.movies.get(id)) |movie| {
                const json = std.json.stringifyAlloc(self.allocator, movie, .{}) catch return;
                defer self.allocator.free(json);
                r.sendJson(json) catch return;
                return;
            }
        }
    }
    r.setStatus(zap.StatusCode.not_found);
    r.sendJson("") catch return;
}

fn listMovies(self: *Self, r: zap.SimpleRequest) void {
    if (self.movies.toJSON()) |json| {
        defer self.allocator.free(json);
        r.sendJson(json) catch return;
    } else |err| {
        std.debug.print("LIST error: {}\n", .{err});
    }
}
