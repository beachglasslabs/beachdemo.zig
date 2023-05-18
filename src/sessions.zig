const std = @import("std");
const Users = @import("users.zig");
const User = Users.User;
const uuid = @import("uuid.zig");

alloc: std.mem.Allocator = undefined,
sessions: std.StringHashMap(Session) = undefined,
lock: std.Thread.Mutex = undefined,

pub const Self = @This();

pub const Session = struct {
    id: [36]u8 = undefined,
    user: *const User = undefined,
};

pub fn init(a: std.mem.Allocator) Self {
    return .{
        .alloc = a,
        .sessions = std.StringHashMap(Session).init(a),
        .lock = std.Thread.Mutex{},
    };
}

pub fn deinit(self: *Self) void {
    self.sessions.deinit();
}

// the request will be freed (and its mem reused by facilio) when it's
// completed, so we take copies of the names
pub fn login(self: *Self, user: *const User) ![]const u8 {
    var session: Session = undefined;

    session.user = user;

    // We lock only on insertion, deletion, and listing
    self.lock.lock();
    defer self.lock.unlock();
    _ = try std.fmt.bufPrint(&session.id, "{s}", .{uuid.newV4()});
    if (self.sessions.put(&session.id, session)) {
        return &session.id;
    } else |err| {
        std.debug.print("create error: {}\n", .{err});
        // make sure we pass on the error
        return err;
    }
}

pub fn delete(self: *Self, id: []const u8) bool {
    // We lock only on insertion, deletion, and listing
    self.lock.lock();
    defer self.lock.unlock();

    return self.sessions.remove(id);
}

pub fn get(self: *Self, id: []const u8) ?Session {
    // we don't care about locking here, as our usage-pattern is unlikely to
    // get a session by id that is not known yet
    if (self.sessions.getPtr(id)) |pSession| {
        return .{
            .id = pSession.id,
            .user = pSession.user,
        };
    }
    return null;
}

pub fn toJSON(self: *Self) ![]const u8 {
    self.lock.lock();
    defer self.lock.unlock();

    // We create a Session list that's JSON-friendly
    // NOTE: we could also implement the whole JSON writing ourselves here,
    // working directly with InternalSession elements of the sessions hashmap.
    // might actually save some memory
    // TODO: maybe do it directly with the session.items
    var l: std.ArrayList(Session) = std.ArrayList(Session).init(self.alloc);
    defer l.deinit();

    // the potential race condition is fixed by jsonifying with the mutex locked
    var it = JsonSessionIteratorWithRaceCondition.init(&self.sessions);
    while (it.next()) |session| {
        try l.append(session);
    }
    std.debug.assert(self.sessions.count() == l.items.len);
    return std.json.stringifyAlloc(self.alloc, l.items, .{});
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
                .user = pSession.*.user,
            };
            return session;
        }
        return null;
    }
};
