const std = @import("std");
const zap = @import("zap");

pub const SessionAuthArgs = struct {
    username_param: []const u8,
    password_param: []const u8,
    auth_page: []const u8,
    white_list: []const []const u8,
    cookie_name: []const u8,
    /// cookie max age in seconds; 0 -> session cookie
    cookie_maxage: u8 = 0,
    /// redirect status code, defaults to 302 found
    redirect_code: zap.StatusCode = .found,
};

/// SessionAuth supports the following use case:
///
/// - checks every request: is it going to the login page? -> let the request through.
/// - else:
///   - checks every request for a session token in a cookie
///   - if there is no token, it checks for correct username and password body params
///     - if username and password are present and correct, it will create a session token,
///       create a response cookie containing the token, and carry on with the request
///     - else it will redirect to the login page
///   - if the session token is present and correct: it will let the request through
///   - else: it will redirect to the login page
///
/// Please note the implications of this simple approach: IF YOU REUSE "username"
/// and "password" body params for anything else in your application, then the
/// mechanisms described above will kick in. For that reason: please know what you're
/// doing.
///
/// See SessionAuthArgs:
/// - username & password param names can be defined by you
/// - session cookie name and max-age can be defined by you
/// - login page and redirect code (.302) can be defined by you
///
/// Comptime Parameters:
///
/// - `Lookup` must implement .get([]const u8) -> []const u8 for user password retrieval
/// - `lockedPwLookups` : if true, accessing the provided Lookup instance will be protected
///    by a Mutex. You can access the mutex yourself via the `passwordLookupLock`.
/// - `lockedTokenLookups` : if true, accessing the internal token table will be protected
///    by a Mutex. You can access the mutex yourself via the `passwordLookupLock`.
///
/// Note: In order to be quick, you can set lockedTokenLookups to false.
///       -> we generate it on init() and leave it static
///       -> there is no way to 100% log out apart from re-starting the server
///       -> because: we send a cookie to the browser that invalidates the session cookie
///       -> another browser program with the page still open would still be able to use
///       -> the session. Which is kindof OK, but not as cool as erasing the token
///       -> on the server side which immediately block all other browsers as well.
pub fn SessionAuth(comptime User: type, comptime Session: type) type {
    return struct {
        allocator: std.mem.Allocator,
        users: *std.StringHashMap(User),
        sessions: *std.StringHashMap(Session),
        settings: SessionAuthArgs,

        sessionTokens: SessionTokenMap,

        const Self = @This();
        const SessionTokenMap = std.StringHashMap(void);
        const Hash = std.crypto.hash.sha2.Sha256;

        const Token = [Hash.digest_length * 2]u8;

        pub fn init(
            allocator: std.mem.Allocator,
            users: *std.StringHashMap(User),
            sessions: *std.StringHashMap(Session),
            args: SessionAuthArgs,
        ) !Self {
            return .{
                .allocator = allocator,
                .users = users,
                .sessions = sessions,
                .settings = .{
                    .username_param = args.username_param,
                    .password_param = args.password_param,
                    .auth_page = args.auth_page,
                    .white_list = args.white_list,
                    .cookie_name = try allocator.dupe(u8, args.cookie_name),
                    .cookie_maxage = args.cookie_maxage,
                    .redirect_code = args.redirect_code,
                },
                .sessionTokens = SessionTokenMap.init(allocator),
            };
        }

        /// Check for session token cookie, remove the token from the valid tokens
        /// Note: only valid if lockedTokenLookups == true
        pub fn logout(self: *Self, r: *const zap.SimpleRequest) void {
            // if we are allowed to lock the table, we can erase the list of valid tokens server-side
            if (r.setCookie(.{
                .name = self.settings.cookie_name,
                .value = "invalid",
                .max_age_s = self.settings.cookie_maxage,
            })) {
                zap.debug("logout ok\n", .{});
            } else |err| {
                zap.debug("logout cookie setting failed: {any}\n", .{err});
            }

            r.parseCookies();

            // check for session cookie
            if (r.getCookieStr(self.settings.cookie_name, self.allocator, false)) |maybe_cookie| {
                if (maybe_cookie) |cookie| {
                    defer cookie.deinit();
                    // if cookie is a valid session, remove it!
                    _ = self.sessionTokens.remove(cookie);
                }
            } else |err| {
                zap.debug("unreachable: SessionAuth.logout: {any}", .{err});
            }
        }

        pub fn deinit(self: *const Self) void {
            self.allocator.free(self.settings.cookie_name);
        }

        fn _internal_authenticateRequest(self: *Self, r: *const zap.SimpleRequest) zap.AuthResult {
            // if we're requesting the login page, let the request through
            if (r.path) |p| {
                for (self.settings.white_list) |page| {
                    if (std.mem.eql(u8, p, page)) {
                        return .AuthOK;
                    }
                }
            }

            // parse body
            r.parseBody() catch {
                // zap.debug("warning: parseBody() failed in SessionAuth: {any}", .{err});
                // this is not an error in case of e.g. gets with querystrings
            };

            r.parseCookies(false);

            // check for session cookie
            if (r.getCookieStr(self.settings.cookie_name, self.allocator, false)) |maybe_cookie| {
                if (maybe_cookie) |cookie| {
                    defer cookie.deinit();
                    // locked or unlocked token lookup
                    if (self.sessionTokens.contains(cookie.str)) {
                        // cookie is a valid session!
                        zap.debug("Auth: COOKIE IS OK!!!!: {s}\n", .{cookie.str});
                        return .AuthOK;
                    } else {
                        zap.debug("Auth: COOKIE IS BAD!!!!: {s}\n", .{cookie.str});
                    }
                }
            } else |err| {
                zap.debug("unreachable: could not check for cookie in SessionAuth: {any}", .{err});
            }

            // get params of username and password
            if (r.getParamStr(self.settings.username_param, self.allocator, false)) |maybe_username| {
                if (maybe_username) |*username| {
                    defer username.deinit();
                    if (r.getParamStr(self.settings.password_param, self.allocator, false)) |maybe_pw| {
                        if (maybe_pw) |*pw| {
                            defer pw.deinit();

                            // now check
                            if (self.users.get(username.str)) |user| {
                                if (user.checkPassword(pw.str)) {
                                    // create session token
                                    if (self.createAndStoreSessionToken(username.str, pw.str)) |token| {
                                        // now set the cookie header
                                        if (r.setCookie(.{
                                            .name = self.settings.cookie_name,
                                            .value = token,
                                            .max_age_s = self.settings.cookie_maxage,
                                        })) {
                                            return .AuthOK;
                                        } else |err| {
                                            zap.debug("could not set session token: {any}", .{err});
                                        }
                                    } else |err| {
                                        zap.debug("could not create session token: {any}", .{err});
                                    }
                                    // errors with token don't mean the auth itself wasn't OK
                                    return .AuthOK;
                                }
                            }
                        }
                    } else |err| {
                        zap.debug("getParamSt() for password failed in SessionAuth: {any}", .{err});
                        return .AuthFailed;
                    }
                }
            } else |err| {
                zap.debug("getParamSt() for user failed in SessionAuth: {any}", .{err});
                return .AuthFailed;
            }
            return .AuthFailed;
        }

        pub fn authenticateRequest(self: *Self, r: *const zap.SimpleRequest) zap.AuthResult {
            switch (self._internal_authenticateRequest(r)) {
                .AuthOK => {
                    // username and pass are ok -> created token, set header, caller can continue
                    return .AuthOK;
                },
                // this does not happen, just for completeness
                .Handled => return .Handled,
                // auth failed -> redirect
                .AuthFailed => {
                    // we need to redirect and return .Handled
                    self.redirect(r) catch |err| {
                        // we just give up
                        zap.debug("redirect() failed in SessionAuth: {any}", .{err});
                    };
                    return .Handled;
                },
            }
        }

        fn redirect(self: *Self, r: *const zap.SimpleRequest) !void {
            try r.redirectTo(self.settings.auth_page, self.settings.redirect_code);
        }

        fn createSessionToken(self: *Self, username: []const u8, password: []const u8) ![]const u8 {
            var hasher = Hash.init(.{});
            hasher.update(username);
            hasher.update(password);
            var digest: [Hash.digest_length]u8 = undefined;
            hasher.final(&digest);
            const token: Token = std.fmt.bytesToHex(digest, .lower);
            const token_str = try self.allocator.dupe(u8, token[0..token.len]);
            return token_str;
        }

        fn createAndStoreSessionToken(self: *Self, username: []const u8, password: []const u8) ![]const u8 {
            const token = try self.createSessionToken(username, password);
            // put locked or not
            if (!self.sessionTokens.contains(token)) {
                try self.sessionTokens.put(token, {});
            }
            return token;
        }
    };
}
