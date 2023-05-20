const std = @import("std");
const uuid = @import("uuid.zig");

alloc: std.mem.Allocator = undefined,
users_by_id: std.StringHashMap(InternalUser) = undefined,
users_by_email: std.StringHashMap(User) = undefined,
lock: std.Thread.Mutex = undefined,

pub const Self = @This();

const InternalUser = struct {
    id: []const u8 = undefined,
    namebuf: [64]u8 = undefined,
    namelen: usize = undefined,
    mailbuf: [64]u8 = undefined,
    maillen: usize = undefined,
    passbuf: [64]u8 = undefined,
    passlen: usize = undefined,
};

pub const User = struct {
    id: []const u8,
    name: []const u8,
    email: []const u8,
    password: []const u8,

    pub fn checkPassword(self: *const User, password: []const u8) bool {
        std.debug.print("checking user.password:{s} with password:{s}\n", .{ self.password, password });
        if (std.mem.eql(u8, self.password, password)) {
            std.debug.print("password is same\n", .{});
            return true;
        }

        return false;
    }
};

pub fn init(a: std.mem.Allocator) Self {
    return .{
        .alloc = a,
        .users_by_id = std.StringHashMap(InternalUser).init(a),
        .users_by_email = std.StringHashMap(User).init(a),
        .lock = std.Thread.Mutex{},
    };
}

pub fn deinit(self: *Self) void {
    self.users_by_email.deinit();
    var iter = self.users_by_id.valueIterator();
    while (iter.next()) |user| {
        defer self.alloc.free(user.id);
    }
    self.users_by_id.deinit();
}

// the request will be freed (and its mem reused by facilio) when it's
// completed, so we take copies of the names
pub fn add(self: *Self, name: ?[]const u8, mail: ?[]const u8, pass: ?[]const u8) ![]const u8 {
    var user: InternalUser = undefined;
    user.namelen = 0;
    user.maillen = 0;
    user.passlen = 0;

    if (name) |username| {
        std.mem.copy(u8, user.namebuf[0..], username);
        user.namelen = username.len;
    }

    if (mail) |usermail| {
        std.mem.copy(u8, user.mailbuf[0..], usermail);
        user.maillen = usermail.len;
    }

    if (pass) |userpass| {
        std.mem.copy(u8, user.passbuf[0..], userpass);
        user.passlen = userpass.len;
    }

    // We lock only on insertion, deletion, and listing
    self.lock.lock();
    defer self.lock.unlock();
    user.id = try std.fmt.allocPrint(self.alloc, "{s}", .{uuid.newV4()});
    if (self.users_by_id.put(user.id, user)) {
        var newUser = self.getById(user.id).?;
        std.debug.print("adding user: {s} as {s}\n", .{ newUser.email, newUser.id });
        if (self.users_by_email.put(newUser.email, newUser)) {
            std.debug.print("user.id:{s} added\n", .{newUser.id});
            return newUser.id;
        } else |err| {
            std.debug.print("add error: {}\n", .{err});
            // make sure we pass on the error
            return err;
        }
    } else |err| {
        std.debug.print("add error: {}\n", .{err});
        // make sure we pass on the error
        return err;
    }
}

pub fn delete(self: *Self, id: []const u8) bool {
    // We lock only on insertion, deletion, and listing
    self.lock.lock();
    defer self.lock.unlock();

    const user = self.users_by_id.fetchRemove(id).?.value;
    defer self.alloc.free(user.id);
    return self.users_by_email.remove(&user.mailbuf);
}

pub fn getBySub(self: *Self, sub: []const u8) ?User {
    std.debug.print("getBySub {s}\n", .{sub});
    if (self.users_by_email.getPtr(sub)) |pUser| {
        std.debug.print("getBySub found {s}\n", .{pUser.id});
        return getById(self, pUser.id);
    }
    return null;
}

pub fn getById(self: *Self, id: []const u8) ?User {
    // we don't care about locking here, as our usage-pattern is unlikely to
    // get a user by id that is not known yet
    if (self.users_by_id.getPtr(id)) |pUser| {
        std.debug.print("getById found {s}\n", .{pUser.id});
        return .{
            .id = pUser.id[0..36],
            .name = pUser.namebuf[0..pUser.namelen],
            .email = pUser.mailbuf[0..pUser.maillen],
            .password = pUser.passbuf[0..pUser.passlen],
        };
    } else {
        std.debug.print("getById cannot find {s}\n", .{id});
    }
    return null;
}

pub fn update(
    self: *Self,
    id: []const u8,
    name: ?[]const u8,
    mail: ?[]const u8,
    pass: ?[]const u8,
) bool {
    // we don't care about locking here
    // we update in-place, via getPtr
    if (self.users_by_id.getPtr(id)) |pUser| {
        if (name) |username| {
            std.mem.copy(u8, pUser.namebuf[0..], username);
            pUser.namelen = username.len;
        }
        if (mail) |usermail| {
            std.mem.copy(u8, pUser.mailbuf[0..], usermail);
            pUser.maillen = usermail.len;
        }
        if (pass) |userpass| {
            std.mem.copy(u8, pUser.passbuf[0..], userpass);
            pUser.passlen = userpass.len;
        }
    }
    return false;
}

pub fn toJSON(self: *Self) ![]const u8 {
    self.lock.lock();
    defer self.lock.unlock();

    // We create a User list that's JSON-friendly
    // NOTE: we could also implement the whole JSON writing ourselves here,
    // working directly with InternalUser elements of the users hashmap.
    // might actually save some memory
    // TODO: maybe do it directly with the user.items
    var l: std.ArrayList(User) = std.ArrayList(User).init(self.alloc);
    defer l.deinit();

    // the potential race condition is fixed by jsonifying with the mutex locked
    var it = JsonUserIteratorWithRaceCondition.init(&self.users_by_id);
    while (it.next()) |user| {
        try l.append(user);
    }
    std.debug.assert(self.users_by_id.count() == l.items.len);
    std.debug.assert(self.users_by_email.count() == l.items.len);
    return std.json.stringifyAlloc(self.alloc, l.items, .{});
}

//
// Note: the following code is kept in here because it taught us a lesson
//
pub fn listWithRaceCondition(self: *Self, out: *std.ArrayList(User)) !void {
    // We lock only on insertion, deletion, and listing
    //
    // NOTE: race condition:
    // =====================
    //
    // the list returned from here contains elements whose slice fields
    // (.first_name and .last_name) point to char buffers of elements of the
    // users list:
    //
    // user.first_name -> internal_user.firstnamebuf[..]
    //
    // -> we're only referencing the memory of first and last names.
    // -> while the caller works with this list, e.g. "slowly" converting it to
    //    JSON, the users hashmap might be added to massively in the background,
    //    causing it to GROW -> realloc -> all slices get invalidated!
    //
    // So, to mitigate that, either:
    // - [x] listing and converting to JSON must become one locked operation
    // - or: the iterator must make copies of the strings
    self.lock.lock();
    defer self.lock.unlock();
    var it = JsonUserIteratorWithRaceCondition.init(&self.users_by_id);
    while (it.next()) |user| {
        try out.append(user);
    }
    std.debug.assert(self.users_by_id.count() == out.items.len);
}

const JsonUserIteratorWithRaceCondition = struct {
    it: std.StringHashMap(InternalUser).ValueIterator = undefined,
    const This = @This();

    // careful:
    // - Self refers to the file's struct
    // - This refers to the JsonUserIterator struct
    pub fn init(internal_users: *std.StringHashMap(InternalUser)) This {
        return .{
            .it = internal_users.valueIterator(),
        };
    }

    pub fn next(this: *This) ?User {
        if (this.it.next()) |pUser| {
            // we get a pointer to the internal user. so it should be safe to
            // create slices from its first and last name buffers
            //
            // SEE ABOVE NOTE regarding race condition why this is can be problematic
            var user: User = .{
                // we don't need .* syntax but want to make it obvious
                .id = pUser.*.id[0..36],
                .name = pUser.*.namebuf[0..pUser.*.namelen],
                .email = pUser.*.mailbuf[0..pUser.*.maillen],
                .password = pUser.*.passbuf[0..pUser.*.passlen],
            };
            if (pUser.*.namelen == 0) {
                user.name = "";
            }
            if (pUser.*.maillen == 0) {
                user.email = "";
            }
            if (pUser.*.passlen == 0) {
                user.password = "";
            }
            return user;
        }
        return null;
    }
};
