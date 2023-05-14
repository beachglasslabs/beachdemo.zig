const std = @import("std");

alloc: std.mem.Allocator = undefined,
sessions: std.AutoHashMap(usize, InternalSession) = undefined,
lock: std.Thread.Mutex = undefined,
count: usize = 0,

pub const Self = @This();

const InternalSession = struct {
    id: usize = 0,
    firstnamebuf: [64]u8,
    firstnamelen: usize,
    lastnamebuf: [64]u8,
    lastnamelen: usize,
};

pub const Session = struct {
    id: usize = 0,
    first_name: []const u8,
    last_name: []const u8,
};

pub fn init(a: std.mem.Allocator) Self {
    return .{
        .alloc = a,
        .sessions = std.AutoHashMap(usize, InternalSession).init(a),
        .lock = std.Thread.Mutex{},
    };
}

pub fn deinit(self: *Self) void {
    self.sessions.deinit();
}

// the request will be freed (and its mem reused by facilio) when it's
// completed, so we take copies of the names
pub fn addByName(self: *Self, first: ?[]const u8, last: ?[]const u8) !usize {
    var session: InternalSession = undefined;
    session.firstnamelen = 0;
    session.lastnamelen = 0;

    if (first) |firstname| {
        std.mem.copy(u8, session.firstnamebuf[0..], firstname);
        session.firstnamelen = firstname.len;
    }

    if (last) |lastname| {
        std.mem.copy(u8, session.lastnamebuf[0..], lastname);
        session.lastnamelen = lastname.len;
    }

    // We lock only on insertion, deletion, and listing
    self.lock.lock();
    defer self.lock.unlock();
    session.id = self.count + 1;
    if (self.sessions.put(session.id, session)) {
        self.count += 1;
        return session.id;
    } else |err| {
        std.debug.print("addByName error: {}\n", .{err});
        // make sure we pass on the error
        return err;
    }
}

pub fn delete(self: *Self, id: usize) bool {
    // We lock only on insertion, deletion, and listing
    self.lock.lock();
    defer self.lock.unlock();

    const ret = self.sessions.remove(id);
    if (ret) {
        self.count -= 1;
    }
    return ret;
}

pub fn get(self: *Self, id: usize) ?Session {
    // we don't care about locking here, as our usage-pattern is unlikely to
    // get a session by id that is not known yet
    if (self.sessions.getPtr(id)) |pSession| {
        return .{
            .id = pSession.id,
            .first_name = pSession.firstnamebuf[0..pSession.firstnamelen],
            .last_name = pSession.lastnamebuf[0..pSession.lastnamelen],
        };
    }
    return null;
}

pub fn update(
    self: *Self,
    id: usize,
    first: ?[]const u8,
    last: ?[]const u8,
) bool {
    // we don't care about locking here
    // we update in-place, via getPtr
    if (self.sessions.getPtr(id)) |pSession| {
        pSession.firstnamelen = 0;
        pSession.lastnamelen = 0;
        if (first) |firstname| {
            std.mem.copy(u8, pSession.firstnamebuf[0..], firstname);
            pSession.firstnamelen = firstname.len;
        }
        if (last) |lastname| {
            std.mem.copy(u8, pSession.lastnamebuf[0..], lastname);
            pSession.lastnamelen = lastname.len;
        }
    }
    return false;
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
    std.debug.assert(self.count == l.items.len);
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
    std.debug.assert(self.count == out.items.len);
}

const JsonSessionIteratorWithRaceCondition = struct {
    it: std.AutoHashMap(usize, InternalSession).ValueIterator = undefined,
    const This = @This();

    // careful:
    // - Self refers to the file's struct
    // - This refers to the JsonSessionIterator struct
    pub fn init(internal_sessions: *std.AutoHashMap(usize, InternalSession)) This {
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
                .first_name = pSession.*.firstnamebuf[0..pSession.*.firstnamelen],
                .last_name = pSession.*.lastnamebuf[0..pSession.*.lastnamelen],
            };
            if (pSession.*.firstnamelen == 0) {
                session.first_name = "";
            }
            if (pSession.*.lastnamelen == 0) {
                session.last_name = "";
            }
            return session;
        }
        return null;
    }
};
