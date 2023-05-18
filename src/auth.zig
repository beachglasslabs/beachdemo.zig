const std = @import("std");
const zap = @import("zap");

pub const CookieSessionAuthArgs = struct {
    cookieName: []const u8,
    /// cookie max age in seconds; 0 -> session cookie
    cookieMaxAge: u32 = 0,
    /// redirect status code, defaults to 302 found
    redirectCode: zap.StatusCode = .found,
};

/// CookieSessionAuth supports the following use case:
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
/// See CookieSessionAuthArgs:
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
pub fn CookieSessionAuth(comptime Lookup: type, comptime lockedPwLookups: bool, comptime lockedTokenLookups: bool) type {
    return struct {
        allocator: std.mem.Allocator,
        lookup: *Lookup,
        settings: zap.CookieSessionAuthArgs,

        // TODO: cookie store per user
        sessionTokens: SessionTokenMap,
        passwordLookupLock: std.Thread.Mutex = .{},
        tokenLookupLock: std.Thread.Mutex = .{},

        const Self = @This();
        const SessionTokenMap = std.StringHashMap(void);
        const Hash = std.crypto.hash.sha2.Sha256;

        const Token = [Hash.digest_length * 2]u8;

        pub fn init(
            allocator: std.mem.Allocator,
            lookup: *Lookup,
            args: CookieSessionAuthArgs,
        ) !Self {
            var ret: Self = .{
                .allocator = allocator,
                .settings = .{
                    .usernameParam = try allocator.dupe(u8, args.usernameParam),
                    .passwordParam = try allocator.dupe(u8, args.passwordParam),
                    .loginPage = try allocator.dupe(u8, args.loginPage),
                    .cookieName = try allocator.dupe(u8, args.cookieName),
                    .cookieMaxAge = args.cookieMaxAge,
                    .redirectCode = args.redirectCode,
                },
                .lookup = lookup,
                .sessionTokens = SessionTokenMap.init(allocator),
            };

            if (lockedTokenLookups == false) {
                // we populate on init and forbid logout()
                var it = lookup.iterator();
                while (it.next()) |kv| {
                    // we iterate over all usernames and passwords, create tokens,
                    // and memorize the tokens
                    _ = try ret.createAndStoreSessionToken(kv.key_ptr.*, kv.value_ptr.*);
                }
            }
            return ret;
        }

        /// Check for session token cookie, remove the token from the valid tokens
        /// Note: only valid if lockedTokenLookups == true
        pub fn logout(self: *Self, r: *const zap.SimpleRequest) void {
            if (lockedTokenLookups == false) {
                if (r.setCookie(.{
                    .name = self.settings.cookieName,
                    .value = "invalid",
                    .max_age_s = self.settings.cookieMaxAge,
                })) {
                    zap.debug("logout ok\n", .{});
                } else |err| {
                    zap.debug("logout cookie setting failed: {any}\n", .{err});
                }
                // @compileLog("WARNING! If lockedTokenLookups==false, logout() cannot erase the token from its internal, server-side list of valid tokens");
                return;
            } else {
                zap.debug("logout cookie setting failed\n", .{});
            }

            // if we are allowed to lock the table, we can erase the list of valid tokens server-side
            if (r.setCookie(.{
                .name = self.settings.cookieName,
                .value = "invalid",
                .max_age_s = self.settings.cookieMaxAge,
            })) {
                zap.debug("logout ok\n", .{});
            } else |err| {
                zap.debug("logout cookie setting failed: {any}\n", .{err});
            }

            r.parseCookies();

            // check for session cookie
            if (r.getCookieStr(self.settings.cookieName, self.allocator, false)) |maybe_cookie| {
                if (maybe_cookie) |cookie| {
                    defer cookie.deinit();
                    self.tokenLookupLock.lock();
                    defer self.tokenLookupLock.unlock();
                    // if cookie is a valid session, remove it!
                    _ = self.sessionTokens.remove(cookie);
                }
            } else |err| {
                zap.debug("unreachable: CookieSessionAuth.logout: {any}", .{err});
            }
        }

        pub fn deinit(self: *const Self) void {
            self.allocator.free(self.settings.usernameParam);
            self.allocator.free(self.settings.passwordParam);
            self.allocator.free(self.settings.loginPage);
            self.allocator.free(self.settings.cookieName);
        }

        fn _internal_authenticateRequest(self: *Self, r: *const zap.SimpleRequest) zap.AuthResult {
            // if we're requesting the login page, let the request through
            if (r.path) |p| {
                if (std.mem.startsWith(u8, p, self.settings.loginPage)) {
                    return .AuthOK;
                }
            }

            // parse body
            r.parseBody() catch {
                // zap.debug("warning: parseBody() failed in CookieSessionAuth: {any}", .{err});
                // this is not an error in case of e.g. gets with querystrings
            };

            r.parseCookies(false);

            // check for session cookie
            if (r.getCookieStr(self.settings.cookieName, self.allocator, false)) |maybe_cookie| {
                if (maybe_cookie) |cookie| {
                    defer cookie.deinit();
                    // locked or unlocked token lookup
                    if (lockedTokenLookups) {
                        self.tokenLookupLock.lock();
                        defer self.tokenLookupLock.unlock();
                        if (self.sessionTokens.contains(cookie.str)) {
                            // cookie is a valid session!
                            zap.debug("Auth: COKIE IS OK!!!!: {s}\n", .{cookie.str});
                            return .AuthOK;
                        } else {
                            zap.debug("Auth: COKIE IS BAD!!!!: {s}\n", .{cookie.str});
                        }
                    } else {
                        if (self.sessionTokens.contains(cookie.str)) {
                            // cookie is a valid session!
                            zap.debug("Auth: COKIE IS OK!!!!: {s}\n", .{cookie.str});
                            return .AuthOK;
                        } else {
                            zap.debug("Auth: COKIE IS BAD!!!!: {s}\n", .{cookie.str});
                        }
                    }
                }
            } else |err| {
                zap.debug("unreachable: could not check for cookie in CookieSessionAuth: {any}", .{err});
            }

            // get params of username and password
            if (r.getParamStr(self.settings.usernameParam, self.allocator, false)) |maybe_username| {
                if (maybe_username) |*username| {
                    defer username.deinit();
                    if (r.getParamStr(self.settings.passwordParam, self.allocator, false)) |maybe_pw| {
                        if (maybe_pw) |*pw| {
                            defer pw.deinit();

                            // now check
                            const correct_pw_optional = brk: {
                                if (lockedPwLookups) {
                                    self.passwordLookupLock.lock();
                                    defer self.passwordLookupLock.unlock();
                                    break :brk self.lookup.*.get(username.str);
                                } else {
                                    break :brk self.lookup.*.get(username.str);
                                }
                            };
                            if (correct_pw_optional) |correct_pw| {
                                if (std.mem.eql(u8, pw.str, correct_pw)) {
                                    // create session token
                                    if (self.createAndStoreSessionToken(username.str, pw.str)) |token| {
                                        // now set the cookie header
                                        if (r.setCookie(.{
                                            .name = self.settings.cookieName,
                                            .value = token,
                                            .max_age_s = self.settings.cookieMaxAge,
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
                        zap.debug("getParamSt() for password failed in CookieSessionAuth: {any}", .{err});
                        return .AuthFailed;
                    }
                }
            } else |err| {
                zap.debug("getParamSt() for user failed in CookieSessionAuth: {any}", .{err});
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
                        zap.debug("redirect() failed in CookieSessionAuth: {any}", .{err});
                    };
                    return .Handled;
                },
            }
        }

        fn redirect(self: *Self, r: *const zap.SimpleRequest) !void {
            try r.redirectTo(self.settings.loginPage, self.settings.redirectCode);
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
            if (lockedTokenLookups) {
                self.tokenLookupLock.lock();
                defer self.tokenLookupLock.unlock();

                if (!self.sessionTokens.contains(token)) {
                    try self.sessionTokens.put(token, {});
                }
            } else {
                if (!self.sessionTokens.contains(token)) {
                    try self.sessionTokens.put(token, {});
                }
            }
            return token;
        }
    };
}
