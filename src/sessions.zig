const std = @import("std");
const uuid = @import("uuid.zig");

allocator: std.mem.Allocator = undefined,
sessions: std.StringHashMap(Session) = undefined,
lock: std.Thread.Mutex = undefined,

pub const Self = @This();

pub const Session = struct {
    id: []const u8 = undefined,
    userid: []const u8 = undefined,
};

pub fn init(a: std.mem.Allocator) Self {
    return .{
        .allocator = a,
        .sessions = std.StringHashMap(Session).init(a),
        .lock = std.Thread.Mutex{},
    };
}

pub fn deinit(self: *Self) void {
    var iter = self.sessions.valueIterator();
    while (iter.next()) |session| {
        defer self.allocator.free(session.id);
    }
    self.sessions.deinit();
}

// the request will be freed (and its mem reused by facilio) when it's
// completed, so we take copies of the names
pub fn create(self: *Self, userid: []const u8) ![]const u8 {
    var session: Session = undefined;

    session.userid = userid;

    // We lock only on insertion, deletion, and listing
    self.lock.lock();
    defer self.lock.unlock();
    session.id = try std.fmt.allocPrint(self.allocator, "{s}", .{uuid.newV4()});
    if (self.sessions.put(session.id, session)) {
        return session.id;
    } else |err| {
        std.debug.print("create error: {}\n", .{err});
        // make sure we pass on the error
        return err;
    }
}

pub fn destroy(self: *Self, id: []const u8) bool {
    // We lock only on insertion, deletion, and listing
    self.lock.lock();
    defer self.lock.unlock();

    if (self.sessions.fetchRemove(id)) |maybe_session| {
        const session = maybe_session.value;
        defer self.allocator.free(session.id);
        return true;
    } else {
        return false;
    }
}

pub fn get(self: *Self, id: []const u8) ?Session {
    // we don't care about locking here, as our usage-pattern is unlikely to
    // get a session by id that is not known yet
    return self.sessions.get(id);
}

pub fn toJSON(self: *Self) ![]const u8 {
    self.lock.lock();
    defer self.lock.unlock();

    // We create a Session list that's JSON-friendly
    // NOTE: we could also implement the whole JSON writing ourselves here,
    // TODO: maybe do it directly with the session.items
    var l: std.ArrayList(Session) = std.ArrayList(Session).init(self.allocator);
    defer l.deinit();

    // the potential race condition is fixed by jsonifying with the mutex locked
    var it = JsonSessionIteratorWithRaceCondition.init(&self.sessions);
    while (it.next()) |session| {
        try l.append(session);
    }
    std.debug.assert(self.sessions.count() == l.items.len);
    return std.json.stringifyAlloc(self.allocator, l.items, .{});
}

//
// Note: the following code is kept in here because it taught us a lesson
//
pub fn listWithRaceCondition(self: *Self, out: *std.ArrayList(Session)) !void {
    // We lock only on insertion, deletion, and listing
    //
    // NOTE: race condition:
    // =====================
    //
    // the list returned from here contains elements whose slice fields
    // (.first_name and .last_name) point to char buffers of elements of the
    // sessions list:
    //
    // session.first_name -> internal_session.firstnamebuf[..]
    //
    // -> we're only referencing the memory of first and last names.
    // -> while the caller works with this list, e.g. "slowly" converting it to
    //    JSON, the sessions hashmap might be added to massively in the background,
    //    causing it to GROW -> realloc -> all slices get invalidated!
    //
    // So, to mitigate that, either:
    // - [x] listing and converting to JSON must become one locked operation
    // - or: the iterator must make copies of the strings
    self.lock.lock();
    defer self.lock.unlock();
    var it = JsonSessionIteratorWithRaceCondition.init(&self.sessions);
    while (it.next()) |session| {
        try out.append(session);
    }
    std.debug.assert(self.sessions.count() == out.items.len);
}

const JsonSessionIteratorWithRaceCondition = struct {
    it: std.StringHashMap(Session).ValueIterator = undefined,
    const This = @This();

    // careful:
    // - Self refers to the file's struct
    // - This refers to the JsonSessionIterator struct
    pub fn init(internal_sessions: *std.StringHashMap(Session)) This {
        return .{
            .it = internal_sessions.valueIterator(),
        };
    }

    pub fn next(this: *This) ?Session {
        if (this.it.next()) |pSession| {
            // we get a pointer to the internal session. so it should be safe to
            // create slices from its first and last name buffers
            //
            // SEE ABOVE NOTE regarding race condition why this is can be problematic
            var session: Session = .{
                // we don't need .* syntax but want to make it obvious
                .id = pSession.*.id,
                .userid = pSession.*.userid,
            };
            return session;
        }
        return null;
    }
};
