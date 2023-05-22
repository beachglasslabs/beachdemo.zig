const std = @import("std");
const uuid = @import("uuid.zig");

allocator: std.mem.Allocator = undefined,
movies: std.StringHashMap(Movie) = undefined,

pub const Self = @This();

pub const Movie = struct {
    title: []const u8,
    description: []const u8,
    videoUrl: []const u8,
    thumbnailUrl: []const u8,
    genre: []const u8,
    duration: []const u8,
};

pub fn init(a: std.mem.Allocator, data_path: []const u8) !Self {
    try fetch_data(a, data_path);

    return .{
        .allocator = a,
        .movies = std.StringHashMap(Movie).init(a),
    };
}

fn fetch_data(a: std.mem.Allocator, filename: []const u8) !void {
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const size = (try file.stat()).size;

    const contents = try file.reader().readAllAlloc(a, size);
    defer a.free(contents);

    var movie = try std.json.parseFromSlice(Movie, a, contents, .{});
    std.debug.print("movies are {any}\n", .{movie});
}

pub fn deinit(self: *Self) void {
    //var iter = self.movies.valueIterator();
    //while (iter.next()) |movie| {
    //    defer self.allocator.free(movie.id);
    //}
    self.movies.deinit();
}

pub fn get(self: *Self, id: []const u8) ?Movie {
    // we don't care about locking here, as our usage-pattern is unlikely to
    // get a movie by id that is not known yet
    return self.movies.get(id);
}

pub fn toJSON(self: *Self) ![]const u8 {

    // We create a Movie list that's JSON-friendly
    // NOTE: we could also implement the whole JSON writing ourselves here,
    // TODO: maybe do it directly with the movie.items
    var l: std.ArrayList(Movie) = std.ArrayList(Movie).init(self.allocator);
    defer l.deinit();

    // the potential race condition is fixed by jsonifying with the mutex locked
    var it = JsonMovieIteratorWithRaceCondition.init(&self.movies);
    while (it.next()) |movie| {
        try l.append(movie);
    }
    std.debug.assert(self.movies.count() == l.items.len);
    return std.json.stringifyAlloc(self.allocator, l.items, .{});
}

//
// Note: the following code is kept in here because it taught us a lesson
//
pub fn listWithRaceCondition(self: *Self, out: *std.ArrayList(Movie)) !void {
    // We lock only on insertion, deletion, and listing
    //
    // NOTE: race condition:
    // =====================
    //
    // the list returned from here contains elements whose slice fields
    // (.first_name and .last_name) point to char buffers of elements of the
    // movies list:
    //
    // movie.first_name -> internal_movie.firstnamebuf[..]
    //
    // -> we're only referencing the memory of first and last names.
    // -> while the caller works with this list, e.g. "slowly" converting it to
    //    JSON, the movies hashmap might be added to massively in the background,
    //    causing it to GROW -> realloc -> all slices get invalidated!
    //
    // So, to mitigate that, either:
    // - [x] listing and converting to JSON must become one locked operation
    // - or: the iterator must make copies of the strings
    self.lock.lock();
    defer self.lock.unlock();
    var it = JsonMovieIteratorWithRaceCondition.init(&self.movies);
    while (it.next()) |movie| {
        try out.append(movie);
    }
    std.debug.assert(self.movies.count() == out.items.len);
}

const JsonMovieIteratorWithRaceCondition = struct {
    it: std.StringHashMap(Movie).ValueIterator = undefined,
    const This = @This();

    // careful:
    // - Self refers to the file's struct
    // - This refers to the JsonMovieIterator struct
    pub fn init(internal_movies: *std.StringHashMap(Movie)) This {
        return .{
            .it = internal_movies.valueIterator(),
        };
    }

    pub fn next(this: *This) ?Movie {
        if (this.it.next()) |pMovie| {
            // we get a pointer to the internal movie. so it should be safe to
            // create slices from its first and last name buffers
            //
            // SEE ABOVE NOTE regarding race condition why this is can be problematic
            var movie: Movie = pMovie.*;
            //std.mem.copy(u8, &movie.title, &pMovie.title);
            //std.mem.copy(u8, &movie.description, &pMovie.description);
            //std.mem.copy(u8, &movie.videoUrl, &pMovie.videoUrl);
            //std.mem.copy(u8, &movie.thumbnailUrl, &pMovie.thumbnailUrl);
            //std.mem.copy(u8, &movie.genre, &pMovie.genre);
            //std.mem.copy(u8, &movie.duration, &pMovie.duration);
            return movie;
        }
        return null;
    }
};
