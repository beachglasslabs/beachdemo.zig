const std = @import("std");
const zap = @import("zap");
const Oauth = @import("oauth2_provider.zig");

pub const AuthSettings = struct {
    name_param: []const u8,
    subject_param: []const u8,
    password_param: []const u8,
    whitelist: []const []const u8,
    success_url: []const u8, // redirect if successful
    failure_url: []const u8, // redirect if failed
    signin_callback: []const u8, // the api endpoint for start a new session
    signup_callback: []const u8, // the api endpoint for adding a new user
    cookie_name: []const u8,
    /// cookie max age in seconds; 0 -> session cookie
    cookie_maxage: i32 = 0,
    /// redirect status code, defaults to 302 found
    redirect_code: zap.StatusCode = .found,
};

pub const OauthSettings = struct {
    google_redirect: []const u8,
    github_redirect: []const u8,
    google_client_id: []const u8,
    github_client_id: []const u8,
    google_client_secret: []const u8,
    github_client_secret: []const u8,
    google_callback: []const u8,
    github_callback: []const u8,
};

const Settings = struct {
    name_param: []const u8,
    subject_param: []const u8,
    password_param: []const u8,
    whitelist: []const []const u8,
    success_url: []const u8, // redirect if successful
    failure_url: []const u8, // redirect if failed
    signin_callback: []const u8, // the api endpoint for start a new session
    signup_callback: []const u8, // the api endpoint for adding a new user
    google_redirect: ?[]const u8,
    github_redirect: ?[]const u8,
    google_callback: ?[]const u8,
    github_callback: ?[]const u8,
    cookie_name: []const u8,
    /// cookie max age in seconds; 0 -> session cookie
    cookie_maxage: i32 = 0,
    /// redirect status code, defaults to 302 found
    redirect_code: zap.StatusCode = .found,
};
/// Authenticator supports the following use case:
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
/// See AuthenticatorSettings:
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
pub fn Authenticator(comptime UserManager: type, comptime SessionManager: type, comptime Context: type) type {
    return struct {
        allocator: std.mem.Allocator,
        users: *UserManager,
        sessions: *SessionManager,
        google: ?Oauth.OauthProvider(Self),
        github: ?Oauth.OauthProvider(Self),
        settings: Settings,

        session_lock: std.Thread.Mutex = .{},
        session_tokens: SessionTokenMap,
        oauth_lock: std.Thread.Mutex = .{},
        oauth_tokens: OauthTokenMap,

        const Self = @This();
        const SessionTokenMap = std.StringHashMap([]const u8);
        const OauthTokenMap = std.StringHashMap(void);
        const Hash = std.crypto.hash.sha2.Sha256;

        const Token = [Hash.digest_length * 2]u8;

        fn getGoogle(allocator: std.mem.Allocator, settings: AuthSettings, oauth: ?OauthSettings) !?Oauth.OauthProvider(Self) {
            if (oauth) |os| {
                return try Oauth.OauthProvider(Self).init(allocator, .{
                    .provider = Oauth.providers.google,
                    .id = os.google_client_id,
                    .secret = os.google_client_secret,
                }, .{
                    .callback_url = os.google_callback,
                    .success_url = settings.success_url,
                });
            } else {
                return null;
            }
        }

        fn getGithub(allocator: std.mem.Allocator, settings: AuthSettings, oauth: ?OauthSettings) !?Oauth.OauthProvider(Self) {
            if (oauth) |os| {
                return try Oauth.OauthProvider(Self).init(allocator, .{
                    .provider = Oauth.providers.github,
                    .id = os.github_client_id,
                    .secret = os.github_client_secret,
                }, .{
                    .callback_url = os.github_callback,
                    .success_url = settings.success_url,
                });
            } else {
                return null;
            }
        }

        pub fn init(
            allocator: std.mem.Allocator,
            users: *UserManager,
            sessions: *SessionManager,
            settings: AuthSettings,
            oauth_settings: ?OauthSettings,
        ) !Self {
            return .{
                .allocator = allocator,
                .users = users,
                .sessions = sessions,
                .google = try getGoogle(allocator, settings, oauth_settings),
                .github = try getGithub(allocator, settings, oauth_settings),
                .settings = .{
                    .name_param = try allocator.dupe(u8, settings.name_param),
                    .subject_param = try allocator.dupe(u8, settings.subject_param),
                    .password_param = try allocator.dupe(u8, settings.password_param),
                    .whitelist = settings.whitelist,
                    .success_url = try allocator.dupe(u8, settings.success_url),
                    .failure_url = try allocator.dupe(u8, settings.failure_url),
                    .signin_callback = try allocator.dupe(u8, settings.signin_callback),
                    .signup_callback = try allocator.dupe(u8, settings.signup_callback),
                    .cookie_name = try allocator.dupe(u8, settings.cookie_name),
                    .cookie_maxage = settings.cookie_maxage,
                    .redirect_code = settings.redirect_code,
                    .google_redirect = if (oauth_settings) |os| os.google_redirect else null,
                    .github_redirect = if (oauth_settings) |os| os.github_redirect else null,
                    .google_callback = if (oauth_settings) |os| os.google_callback else null,
                    .github_callback = if (oauth_settings) |os| os.github_callback else null,
                },
                .session_tokens = SessionTokenMap.init(allocator),
                .oauth_tokens = OauthTokenMap.init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            var siter = self.session_tokens.keyIterator();
            while (siter.next()) |k| {
                self.allocator.free(k.*);
            }
            self.session_tokens.deinit();
            var oiter = self.oauth_tokens.keyIterator();
            while (oiter.next()) |k| {
                self.allocator.free(k.*);
            }
            self.oauth_tokens.deinit();
            if (self.google) |google| google.deinit();
            if (self.github) |github| github.deinit();
            self.allocator.free(self.settings.name_param);
            self.allocator.free(self.settings.subject_param);
            self.allocator.free(self.settings.password_param);
            self.allocator.free(self.settings.success_url);
            self.allocator.free(self.settings.failure_url);
            self.allocator.free(self.settings.signin_callback);
            self.allocator.free(self.settings.signup_callback);
            self.allocator.free(self.settings.cookie_name);
        }

        pub fn saveInfo(r: *const zap.SimpleRequest, provider_id: []const u8, state: []const u8, userinfo: Oauth.UserInfo) !void {
            _ = r.getUserContext(Context);
            std.debug.print("saveInfo: provider={s}\n", .{provider_id});
            std.debug.print("saveInfo: state={s}\n", .{state});
            std.debug.print("saveInfo: name={s}\n", .{userinfo.name.?});
            std.debug.print("saveInfo: email={s}\n", .{userinfo.email.?});
            var name: []const u8 = undefined;
            if (userinfo.name) |maybe_name| {
                name = maybe_name;
            } else if (userinfo.login) |maybe_name| {
                name = maybe_name;
            }
            std.debug.print("saveInfo: name={s}\n", .{name});
        }

        fn redirectSuccess(self: *Self, r: *const zap.SimpleRequest) !void {
            std.debug.print("redirect success: {s}\n", .{self.settings.success_url});
            try r.redirectTo(self.settings.success_url, self.settings.redirect_code);
        }

        fn redirectFailure(self: *Self, r: *const zap.SimpleRequest) !void {
            std.debug.print("redirect failure: {s}\n", .{self.settings.failure_url});
            try r.redirectTo(self.settings.failure_url, self.settings.redirect_code);
        }

        pub fn registerUser(self: *Self, _: *const zap.SimpleRequest, name: []const u8, subject: []const u8, password: []const u8) bool {
            if (self.users.getBySub(subject)) |user| {
                std.debug.print("register.user: {s} already exists, login instead\n", .{user.email});
                // user exists already, log the user in
                return false;
            } else {
                _ = self.users.post(name, subject, password) catch |err| {
                    std.debug.print("register.user: cannot add {s}: {}\n", .{ subject, err });
                };
                return true;
            }
        }

        // return session token if successful, null otherwise
        pub fn loginUser(self: *Self, r: *const zap.SimpleRequest, subject: []const u8, password: []const u8) bool {
            // now check
            std.debug.print("login.user: {s}\n", .{subject});
            if (self.users.getBySub(subject)) |user| {
                std.debug.print("login.user: checking password {s}\n", .{password});
                if (user.checkPassword(subject, password)) {
                    // create session token
                    std.debug.print("login.user: password matches for {s} {s}\n", .{ user.email, user.id });

                    if (self.createAndStoreSessionToken(subject, user.id)) |token| {
                        std.debug.print("login.user: session creation: {s}\n", .{token});
                        defer self.allocator.free(token);
                        // now set the cookie header
                        r.setCookie(.{
                            .name = self.settings.cookie_name,
                            .value = token,
                            .max_age_s = self.settings.cookie_maxage,
                        }) catch |err| {
                            std.debug.print("login.user: cookie setting failed: {}\n", .{err});
                        };
                        // errors with token don't mean the auth itself wasn't OK
                        return true;
                    } else |err| {
                        std.debug.print("login.user: session creation failed: {}\n", .{err});
                        return false;
                    }
                } else {
                    std.debug.print("login.user: password didn't match\n", .{});
                }
            }

            return false;
        }

        // cookie authentication only
        pub fn loginSession(self: *Self, r: *const zap.SimpleRequest) bool {
            r.parseCookies(false);

            // check for session cookie
            if (r.getCookieStr(self.settings.cookie_name, self.allocator, false)) |maybe_cookie| {
                if (maybe_cookie) |cookie| {
                    defer cookie.deinit();
                    // locked or unlocked token lookup
                    std.debug.print("login.session: cookie {s}\n", .{cookie.str});
                    self.session_lock.lock();
                    defer self.session_lock.unlock();
                    if (self.session_tokens.contains(cookie.str)) {
                        // cookie is a valid session!
                        std.debug.print("login.session: COOKIE IS OK!!!: {s}\n", .{cookie.str});
                        // cookie is a valid session!
                        const sessionid = self.session_tokens.get(cookie.str) orelse return true;
                        const session = self.sessions.get(sessionid) orelse return true;
                        var user = self.users.get(session.userid) orelse return true;
                        std.debug.print("current.user: found {s}\n", .{user.name});
                        if (r.getUserContext(Context)) |c| {
                            c.user = user;
                            r.setUserContext(c);
                        } else {
                            std.debug.print("current.user: woops no context\n", .{});
                        }
                        return true;
                    } else {
                        std.debug.print("login.session: COOKIE IS BAD!!!: {s}\n", .{cookie.str});
                    }
                } else {
                    std.debug.print("login.session: no cookie found\n", .{});
                }
            } else |err| {
                std.debug.print("unreachable: could not check for cookie in login.session: {}\n", .{err});
            }

            return false;
        }

        /// Check for session token cookie, remove the token from the valid tokens
        /// Note: only valid if lockedTokenLookups == true
        pub fn logout(self: *Self, r: *const zap.SimpleRequest) void {
            // if we are allowed to lock the table, we can erase the list of valid tokens server-side
            if (r.setCookie(.{
                .name = self.settings.cookie_name,
                .value = "invalid",
                .max_age_s = -1,
            })) {
                std.debug.print("logout: ok\n", .{});
            } else |err| {
                std.debug.print("logout: cookie setting failed: {}\n", .{err});
            }

            if (r.getUserContext(Context)) |c| {
                c.user = null;
                r.setUserContext(c);
            }

            r.parseCookies(false);

            // check for session cookie
            if (r.getCookieStr(self.settings.cookie_name, self.allocator, false)) |maybe_cookie| {
                if (maybe_cookie) |cookie| {
                    std.debug.print("logout: removing cookie {s}\n", .{cookie.str});
                    defer cookie.deinit();
                    // if cookie is a valid session, remove it!
                    self.session_lock.lock();
                    defer self.session_lock.unlock();
                    if (self.session_tokens.fetchRemove(cookie.str)) |maybe_session| {
                        const token = maybe_session.key;
                        defer self.allocator.free(token);
                        const sessionid = maybe_session.value;
                        std.debug.print("logout: removing session id {s}\n", .{sessionid});
                        _ = self.sessions.delete(sessionid);
                    }
                }
            } else |err| {
                std.debug.print("unreachable: logout: {any}", .{err});
            }
        }

        fn _internal_authenticate(self: *Self, r: *const zap.SimpleRequest) zap.AuthResult {
            const eql = std.mem.eql;
            const s = self.settings;

            // if we're requesting the login page, let the request through
            if (r.path) |p| {
                if (r.method) |m| {
                    std.debug.print("internal.authenticate: {s}.{s}\n", .{ m, p });
                    if (eql(u8, m, "GET")) {
                        for (self.settings.whitelist) |url| {
                            if (std.mem.eql(u8, p, url)) {
                                std.debug.print("internal.authenticateRequest: whitelisted {s}\n", .{p});
                                return .Handled;
                            }
                        }
                        if (self.google) |google| {
                            if (std.mem.eql(u8, p, self.settings.google_redirect.?)) {
                                std.debug.print("google.redirect: {s}\n", .{p});
                                google.redirect(r, "blahblahblah") catch |err| {
                                    std.debug.print("google.redirect: error {}\n", .{err});
                                    return .AuthFailed;
                                };
                                return .Handled;
                            } else if (std.mem.eql(u8, p, self.settings.google_callback.?)) {
                                std.debug.print("google.callback: {s}\n", .{p});
                                google.callback(r) catch |err| {
                                    std.debug.print("google.redirect: error {}\n", .{err});
                                    return .AuthFailed;
                                };
                                return .Handled;
                            }
                        }
                        if (self.github) |github| {
                            if (std.mem.eql(u8, p, self.settings.github_redirect.?)) {
                                std.debug.print("github.redirect: {s}\n", .{p});
                                github.redirect(r, "blahblahblah") catch |err| {
                                    std.debug.print("github.redirect: error {}\n", .{err});
                                    return .AuthFailed;
                                };
                                return .Handled;
                            } else if (std.mem.eql(u8, p, self.settings.github_callback.?)) {
                                std.debug.print("github.callback: {s}\n", .{p});
                                github.callback(r) catch |err| {
                                    std.debug.print("github.redirect: error {}\n", .{err});
                                    return .AuthFailed;
                                };
                                return .Handled;
                            }
                        }
                    }

                    // parse body
                    r.parseBody() catch {
                        // std.debug.print("warning: parseBody() failed in Authenticator: {any}", .{err});
                        // this is not an error in case of e.g. gets with querystrings
                    };

                    var isLogin = eql(u8, p, s.signin_callback);
                    var isRegister = eql(u8, p, s.signup_callback);
                    if (eql(u8, m, "POST") and (isLogin or isRegister)) {
                        std.debug.print("internal.authenticate: login:{} or register:{}\n", .{ isLogin, isRegister });
                        // get params of subject and password
                        if (r.getParamStr(self.settings.subject_param, self.allocator, false)) |maybe_subject| {
                            if (maybe_subject) |*subject| {
                                defer subject.deinit();
                                std.debug.print("internal.authenticate: sub:{s}\n", .{subject.str});
                                if (r.getParamStr(self.settings.password_param, self.allocator, false)) |maybe_password| {
                                    if (maybe_password) |*password| {
                                        defer password.deinit();
                                        std.debug.print("internal.authenticate: password:{s}\n", .{password.str});
                                        if (isRegister) {
                                            if (r.getParamStr(self.settings.name_param, self.allocator, false)) |maybe_name| {
                                                if (maybe_name) |*name| {
                                                    defer name.deinit();
                                                    std.debug.print("internal.authenticate: name:{s}\n", .{name.str});

                                                    _ = self.registerUser(r, name.str, subject.str, password.str);
                                                    isLogin = true;
                                                }
                                            } else |err| {
                                                std.debug.print("internal.authenticate: getParamStr(name) failed: {}\n", .{err});
                                                return .AuthFailed;
                                            }
                                        }
                                        if (isLogin) {
                                            if (self.loginUser(r, subject.str, password.str)) {
                                                self.redirectSuccess(r) catch |err| {
                                                    std.debug.print("internal.authenticate: redirect failed: {}\n", .{err});
                                                };
                                                std.debug.print("internal.authenticate: login success: {s}\n", .{subject.str});
                                                return .Handled;
                                            } else {
                                                std.debug.print("internal.authenticate: login failure: {s}\n", .{subject.str});
                                                return .AuthFailed;
                                            } // else let session endpoint to render the page
                                        }
                                    }
                                } else |err| {
                                    std.debug.print("internal.authenticate: getParamStr(password) failed: {}", .{err});
                                    return .AuthFailed;
                                }
                            }
                        } else |err| {
                            std.debug.print("internal.authenticate: getParamStr(email) failed: {}", .{err});
                            return .AuthFailed;
                        }
                    } else if (eql(u8, m, "DELETE") and isLogin) {
                        std.debug.print("internal.authenticate: logout\n", .{});
                        self.logout(r);
                        // as soon as you log out you failed auth
                        return .AuthFailed;
                    }
                }

                std.debug.print("internal.authenticate: going for auth\n", .{});

                if (self.loginSession(r)) {
                    return .AuthOK;
                }
            }

            return .AuthFailed;
        }

        pub fn authenticateRequest(self: *Self, r: *const zap.SimpleRequest) zap.AuthResult {
            switch (self._internal_authenticate(r)) {
                .AuthOK => {
                    std.debug.print("auth.authenticateRequest: returning .AuthOk\n", .{});
                    return .AuthOK;
                },
                // this does not happen, just for completeness
                .Handled => {
                    // subject and pass are ok -> created token, set header, caller can continue
                    std.debug.print("auth.authenticateRequest: returning .Handled\n", .{});
                    return .Handled;
                },
                // auth failed -> redirect
                .AuthFailed => {
                    // redirect to sigin page and return .Handled
                    self.redirectFailure(r) catch |err| {
                        std.debug.print("auth.authenticate: redirect failed: {}\n", .{err});
                    };
                    return .Handled;
                },
            }
        }

        fn createSessionToken(self: *Self, subject: []const u8, sessionid: []const u8) ![]const u8 {
            var hasher = Hash.init(.{});
            hasher.update(subject);
            hasher.update(sessionid);
            var digest: [Hash.digest_length]u8 = undefined;
            hasher.final(&digest);
            const token: Token = std.fmt.bytesToHex(digest, .lower);
            const token_str = try self.allocator.dupe(u8, token[0..token.len]);
            return token_str;
        }

        fn createAndStoreSessionToken(self: *Self, subject: []const u8, userid: []const u8) ![]const u8 {
            // sessionid should not be freed as sessions will free it
            const sessionid = try self.sessions.post(userid);
            // token should be freed
            const token = try self.createSessionToken(subject, sessionid);
            std.debug.print("create token={s}\n", .{token});
            self.session_lock.lock();
            defer self.session_lock.unlock();
            if (!self.session_tokens.contains(token)) {
                std.debug.print("putting token={s}\n", .{token});
                try self.session_tokens.put(try self.allocator.dupe(u8, token), sessionid);
            }
            return token;
        }
    };
}
