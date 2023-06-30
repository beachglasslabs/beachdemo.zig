const std = @import("std");
const uuid = @import("uuid.zig");

allocator: std.mem.Allocator = undefined,
movies: std.StringHashMap(Movie) = undefined,

pub const Self = @This();

pub const Movie = struct {
    id: []const u8 = "",
    title: []const u8,
    description: []const u8,
    videoUrl: []const u8,
    thumbnailUrl: []const u8,
    genre: []const u8,
    duration: []const u8,
};

pub fn init(a: std.mem.Allocator, data_path: []const u8) !Self {
    var movies = std.StringHashMap(Movie).init(a);
    try fetch_data(&movies, a, data_path);
    std.debug.print("movies: found {d} movies\n", .{movies.count()});
    return .{
        .allocator = a,
        .movies = movies,
    };
}

fn fetch_data(movies: *std.StringHashMap(Movie), a: std.mem.Allocator, filename: []const u8) !void {
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const size = (try file.stat()).size;

    const contents = try file.reader().readAllAlloc(a, size);
    defer a.free(contents);

    const movielist = try std.json.parseFromSlice([]const Movie, a, contents, .{
        .ignore_unknown_fields = true,
    });
    defer movielist.deinit();

    for (movielist.value) |m| {
        var movie: Movie = undefined;
        movie.id = try std.fmt.allocPrint(a, "{s}", .{uuid.newV4()});
        movie.title = try a.dupe(u8, m.title);
        movie.description = try a.dupe(u8, m.description);
        movie.videoUrl = try a.dupe(u8, m.videoUrl);
        movie.thumbnailUrl = try a.dupe(u8, m.thumbnailUrl);
        movie.genre = try a.dupe(u8, m.genre);
        movie.duration = try a.dupe(u8, m.duration);
        std.debug.print("movie: {s}={s}\n", .{ movie.id, movie.title });
        try movies.put(movie.id, movie);
    }
}

pub fn deinit(self: *Self) void {
    var iter = self.movies.valueIterator();
    while (iter.next()) |movie| {
        defer self.allocator.free(movie.id);
        defer self.allocator.free(movie.title);
        defer self.allocator.free(movie.description);
        defer self.allocator.free(movie.videoUrl);
        defer self.allocator.free(movie.thumbnailUrl);
        defer self.allocator.free(movie.genre);
        defer self.allocator.free(movie.duration);
    }
    self.movies.deinit();
}

pub fn get(self: *Self, id: []const u8) ?Movie {
    // we don't care about locking here, as our usage-pattern is unlikely to
    // get a movie by id that is not known yet
    return self.movies.get(id);
}

pub fn random(self: *Self) ?Movie {
    var rng = std.rand.DefaultPrng.init(@as(u64, @intCast(std.time.timestamp())));
    const r = rng.random();

    const n = r.uintLessThan(u32, self.movies.count());
    std.debug.print("movie.random: {d}\n", .{n});
    var iter = self.movies.valueIterator();
    var i: u32 = 0;
    while (iter.next()) |movie| {
        if (i == n) {
            std.debug.print("movie.random: returning {s}\n", .{movie.id});
            return movie.*;
        }
        i += 1;
    }
    return null;
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
            return pMovie.*;
        }
        return null;
    }
};
