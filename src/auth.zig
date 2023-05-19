const std = @import("std");
const zap = @import("zap");

pub const SessionAuthArgs = struct {
    name_param: []const u8,
    subject_param: []const u8,
    password_param: []const u8,
    signin_url: []const u8, // login page
    signin_callback: []const u8, // the api endpoint for start a new session
    signin_success: []const u8, // redirect page after successful login
    signup_url: []const u8, // register page
    signup_callback: []const u8, // the api endpoint for adding a new user
    signup_success: []const u8, // redirect page after successful register
    cookie_name: []const u8,
    /// cookie max age in seconds; 0 -> session cookie
    cookie_maxage: i32 = 0,
    /// redirect status code, defaults to 302 found
    redirect_code: zap.StatusCode = .found,
};

/// SessionAuth supports the following use case:
///
/// - checks every request: is it going to the login page? -> let the request through.
/// - else:
///   - checks every request for a session token in a cookie
///   - if there is no token, it checks for correct subject and password body params
///     - if subject and password are present and correct, it will create a session token,
///       create a response cookie containing the token, and carry on with the request
///     - else it will redirect to the login page
///   - if the session token is present and correct: it will let the request through
///   - else: it will redirect to the login page
///
/// Please note the implications of this simple approach: IF YOU REUSE "subject"
/// and "password" body params for anything else in your application, then the
/// mechanisms described above will kick in. For that reason: please know what you're
/// doing.
///
/// See SessionAuthArgs:
/// - subject & password param names can be defined by you
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
pub fn SessionAuth(comptime UserManager: type, comptime SessionManager: type) type {
    return struct {
        allocator: std.mem.Allocator,
        users: *UserManager,
        sessions: *SessionManager,
        settings: SessionAuthArgs,

        sessionTokens: SessionTokenMap,

        const Self = @This();
        const SessionTokenMap = std.StringHashMap(void);
        const Hash = std.crypto.hash.sha2.Sha256;

        const Token = [Hash.digest_length * 2]u8;

        pub fn init(
            allocator: std.mem.Allocator,
            users: *UserManager,
            sessions: *SessionManager,
            args: SessionAuthArgs,
        ) !Self {
            return .{
                .allocator = allocator,
                .users = users,
                .sessions = sessions,
                .settings = .{
                    .name_param = args.name_param,
                    .subject_param = args.subject_param,
                    .password_param = args.password_param,
                    .signin_url = args.signin_url,
                    .signin_callback = args.signin_callback,
                    .signin_success = args.signin_success,
                    .signup_url = args.signup_url,
                    .signup_callback = args.signup_callback,
                    .signup_success = args.signup_success,
                    .cookie_name = args.cookie_name,
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
                std.debug.print("logout ok\n", .{});
            } else |err| {
                std.debug.print("logout cookie setting failed: {any}\n", .{err});
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
                std.debug.print("unreachable: SessionAuth.logout: {any}", .{err});
            }
        }

        pub fn deinit(self: *const Self) void {
            self.allocator.free(self.settings.cookie_name);
        }

        fn _internal_authenticateRequest(self: *Self, r: *const zap.SimpleRequest) zap.AuthResult {
            const eql = std.mem.eql;
            const s = self.settings;

            // if we're requesting the login page, let the request through
            if (r.path) |p| {
                std.debug.print("in internal.authenticateRequest: {s}\n", .{p});
                if (eql(u8, p, s.signup_url) or eql(u8, p, s.signin_url)) {
                    std.debug.print("in internal.authenticateRequest: signin or signup page\n", .{});
                    return .AuthOK;
                }

                // parse body
                r.parseBody() catch {
                    // std.debug.print("warning: parseBody() failed in SessionAuth: {any}", .{err});
                    // this is not an error in case of e.g. gets with querystrings
                };

                var login = eql(u8, p, s.signin_callback);
                var register = eql(u8, p, s.signup_callback);
                if (login or register) {
                    std.debug.print("in internal.authenticateRequest: login:{} or register:{}\n", .{ login, register });
                    // get params of subject and password
                    if (r.getParamStr(self.settings.subject_param, self.allocator, false)) |maybe_subject| {
                        if (maybe_subject) |*subject| {
                            defer subject.deinit();
                            std.debug.print("in internal.authenticateRequest: sub:{s}\n", .{subject.str});
                            if (r.getParamStr(self.settings.password_param, self.allocator, false)) |maybe_password| {
                                if (maybe_password) |*password| {
                                    defer password.deinit();
                                    std.debug.print("in internal.authenticateRequest: password:{s}\n", .{password.str});
                                    if (register) {
                                        if (r.getParamStr(self.settings.name_param, self.allocator, false)) |maybe_name| {
                                            if (maybe_name) |*name| {
                                                defer name.deinit();
                                                std.debug.print("in internal.authenticateRequest: name:{s}\n", .{name.str});

                                                if (self.users.getBySub(subject.str)) |user| {
                                                    std.debug.print("{s} already exists, login instead\n", .{user.email});
                                                    // user exists already, log the user in
                                                    login = true;
                                                } else {
                                                    const id = self.users.add(name.str, subject.str, password.str) catch |err| {
                                                        std.debug.print("cannot add {s}: {}\n", .{ subject.str, err });
                                                        return .AuthFailed;
                                                    };
                                                    std.debug.print("{s} added as user {s}\n", .{ subject.str, id });
                                                    login = true;
                                                }
                                            }
                                        } else |err| {
                                            std.debug.print("getParamStr() for name failed in SessionAuth: {}\n", .{err});
                                            return .AuthFailed;
                                        }
                                    }
                                    if (login) {
                                        // now check
                                        if (self.users.getBySub(subject.str)) |user| {
                                            if (user.checkPassword(password.str)) {
                                                // create session token
                                                std.debug.print("password matches for {s} {s}", .{ user.email, user.id });

                                                if (self.createAndStoreSessionToken(subject.str, password.str)) |token| {
                                                    // now set the cookie header
                                                    if (r.setCookie(.{
                                                        .name = self.settings.cookie_name,
                                                        .value = token,
                                                        .max_age_s = self.settings.cookie_maxage,
                                                    })) {
                                                        return .AuthOK;
                                                    } else |err| {
                                                        std.debug.print("could not set session token: {any}", .{err});
                                                    }
                                                } else |err| {
                                                    std.debug.print("could not create session token: {any}", .{err});
                                                }
                                                // errors with token don't mean the auth itself wasn't OK
                                                return .AuthOK;
                                            } else {
                                                std.debug.print("password didn't match in SessionAuth", .{});
                                                return .AuthFailed;
                                            }
                                        }
                                    }
                                }
                            } else |err| {
                                std.debug.print("getParamStr() for password failed in SessionAuth: {any}", .{err});
                                return .AuthFailed;
                            }
                        }
                    } else |err| {
                        std.debug.print("getParamStr() for user failed in SessionAuth: {any}", .{err});
                        return .AuthFailed;
                    }
                }

                std.debug.print("in internal.authenticateRequest: going for auth\n", .{});

                r.parseCookies(false);

                // check for session cookie
                if (r.getCookieStr(self.settings.cookie_name, self.allocator, false)) |maybe_cookie| {
                    if (maybe_cookie) |cookie| {
                        defer cookie.deinit();
                        // locked or unlocked token lookup
                        if (self.sessionTokens.contains(cookie.str)) {
                            // cookie is a valid session!
                            std.debug.print("Auth: COOKIE IS OK!!!!: {s}\n", .{cookie.str});
                            return .AuthOK;
                        } else {
                            std.debug.print("Auth: COOKIE IS BAD!!!!: {s}\n", .{cookie.str});
                        }
                    }
                } else |err| {
                    std.debug.print("unreachable: could not check for cookie in SessionAuth: {any}", .{err});
                }
            }

            return .AuthFailed;
        }

        pub fn authenticateRequest(self: *Self, r: *const zap.SimpleRequest) zap.AuthResult {
            std.debug.print("in auth.authenticateRequest\n", .{});
            switch (self._internal_authenticateRequest(r)) {
                .AuthOK => {
                    std.debug.print("in auth.authenticateRequest returning .AuthOk\n", .{});
                    // subject and pass are ok -> created token, set header, caller can continue
                    return .AuthOK;
                },
                // this does not happen, just for completeness
                .Handled => return .Handled,
                // auth failed -> redirect
                .AuthFailed => {
                    // we need to redirect and return .Handled
                    self.redirect(r) catch |err| {
                        // we just give up
                        std.debug.print("redirect() failed in SessionAuth: {any}", .{err});
                    };
                    return .Handled;
                },
            }
        }

        fn redirect(self: *Self, r: *const zap.SimpleRequest) !void {
            try r.redirectTo(self.settings.signin_url, self.settings.redirect_code);
        }

        fn createSessionToken(self: *Self, subject: []const u8, password: []const u8) ![]const u8 {
            var hasher = Hash.init(.{});
            hasher.update(subject);
            hasher.update(password);
            var digest: [Hash.digest_length]u8 = undefined;
            hasher.final(&digest);
            const token: Token = std.fmt.bytesToHex(digest, .lower);
            const token_str = try self.allocator.dupe(u8, token[0..token.len]);
            return token_str;
        }

        fn createAndStoreSessionToken(self: *Self, subject: []const u8, password: []const u8) ![]const u8 {
            const token = try self.createSessionToken(subject, password);
            // put locked or not
            if (!self.sessionTokens.contains(token)) {
                try self.sessionTokens.put(token, {});
            }
            return token;
        }
    };
}
