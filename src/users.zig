const std = @import("std");
const uuid = @import("uuid.zig");

allocator: std.mem.Allocator = undefined,
users_by_id: std.StringHashMap(InternalUser) = undefined,
users_by_email: std.StringHashMap(User) = undefined,
lock: std.Thread.Mutex = undefined,

pub const Self = @This();

const Hash = std.crypto.hash.sha2.Sha256;

const avatar_images = [_][]const u8{ "/img/default-blue.png", "/img/default-red.png", "/img/default-slate.png", "/img/default-green.png" };

const InternalUser = struct {
    id: []const u8 = undefined,
    namebuf: [64]u8 = undefined,
    namelen: usize = undefined,
    mailbuf: [64]u8 = undefined,
    maillen: usize = undefined,
    hashbuf: [Hash.digest_length * 2]u8 = undefined,
    avatar: []const u8 = undefined,
};

pub const User = struct {
    id: []const u8,
    name: []const u8,
    email: []const u8,
    hash: []const u8,
    avatar: []const u8,

    pub fn checkPassword(self: *const User, subject: []const u8, password: []const u8) bool {
        var hasher = Hash.init(.{});
        hasher.update(subject);
        hasher.update(password);
        var digest: [Hash.digest_length]u8 = undefined;
        hasher.final(&digest);
        const hash = std.fmt.bytesToHex(digest, .lower);
        return std.mem.eql(u8, self.hash, &hash);
    }
};

pub fn newAvatarImage() []const u8 {
    var rng = std.rand.DefaultPrng.init(@intCast(u64, std.time.timestamp()));
    const random = rng.random();

    const i = random.uintLessThan(u8, avatar_images.len);
    return avatar_images[i];
}

pub fn hashPassword(buf: []u8, subject: []const u8, password: []const u8) !void {
    var hasher = Hash.init(.{});
    hasher.update(subject);
    hasher.update(password);
    var digest: [Hash.digest_length]u8 = undefined;
    hasher.final(&digest);
    const hash = std.fmt.bytesToHex(digest, .lower);
    std.mem.copy(u8, buf, &hash);
}

pub fn init(a: std.mem.Allocator) Self {
    return .{
        .allocator = a,
        .users_by_id = std.StringHashMap(InternalUser).init(a),
        .users_by_email = std.StringHashMap(User).init(a),
        .lock = std.Thread.Mutex{},
    };
}

pub fn deinit(self: *Self) void {
    self.users_by_email.deinit();
    var iter = self.users_by_id.valueIterator();
    while (iter.next()) |user| {
        defer self.allocator.free(user.id);
    }
    self.users_by_id.deinit();
}

// the request will be freed (and its mem reused by facilio) when it's
// completed, so we take copies of the names
pub fn add(self: *Self, name: []const u8, mail: []const u8, pass: []const u8) ![]const u8 {
    var user: InternalUser = undefined;
    user.namelen = 0;
    user.maillen = 0;

    std.mem.copy(u8, user.namebuf[0..], name);
    user.namelen = name.len;

    std.mem.copy(u8, user.mailbuf[0..], mail);
    user.maillen = mail.len;

    try hashPassword(&user.hashbuf, mail, pass);

    // We lock only on insertion, deletion, and listing
    self.lock.lock();
    defer self.lock.unlock();
    user.id = try std.fmt.allocPrint(self.allocator, "{s}", .{uuid.newV4()});
    user.avatar = newAvatarImage();
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
    defer self.allocator.free(user.id);
    return self.users_by_email.remove(&user.mailbuf);
}

pub fn getByEmail(self: *Self, sub: []const u8) ?User {
    std.debug.print("getByEmail{s}\n", .{sub});
    if (self.users_by_email.getPtr(sub)) |pUser| {
        std.debug.print("getByEmail found {s}\n", .{pUser.id});
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
            .id = pUser.id,
            .name = pUser.namebuf[0..pUser.namelen],
            .email = pUser.mailbuf[0..pUser.maillen],
            .hash = &pUser.hashbuf,
            .avatar = pUser.avatar,
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
            if (pass) |userpass| {
                hashPassword(&pUser.hashbuf, usermail, userpass) catch return false;
            }
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
    var l: std.ArrayList(User) = std.ArrayList(User).init(self.allocator);
    defer l.deinit();

    // the potential race condition is fixed by jsonifying with the mutex locked
    var it = JsonUserIteratorWithRaceCondition.init(&self.users_by_id);
    while (it.next()) |user| {
        try l.append(user);
    }
    std.debug.assert(self.users_by_id.count() == l.items.len);
    std.debug.assert(self.users_by_email.count() == l.items.len);
    return std.json.stringifyAlloc(self.allocator, l.items, .{});
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
                .id = pUser.*.id,
                .name = pUser.*.namebuf[0..pUser.*.namelen],
                .email = pUser.*.mailbuf[0..pUser.*.maillen],
                .hash = &pUser.*.hashbuf,
                .avatar = pUser.*.avatar,
            };
            if (pUser.*.namelen == 0) {
                user.name = "";
            }
            if (pUser.*.maillen == 0) {
                user.email = "";
            }
            return user;
        }
        return null;
    }
};
