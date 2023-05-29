//! https://oauth.net/2/
// part of the code adapted from https://github.com/nektro/zig-oauth2

const std = @import("std");
const zap = @import("zap");
const string = []const u8;
const Params = @import("params.zig");
const Base = @This();

pub const Provider = struct {
    id: string,
    auth_url: string,
    token_url: string,
    user_url: string,
    scope: string = "",
    name_prop: string,
    name_prefix: string = "",
    id_prop: string = "id",

    pub fn domain(self: Provider) string {
        if (std.mem.indexOfScalar(u8, self.id, ',')) |_| {
            var iter = std.mem.split(u8, self.id, ",");
            _ = iter.next();
            return iter.next().?;
        }
        return self.id;
    }
};

pub const Client = struct {
    provider: Provider,
    id: string,
    secret: string,
};

pub const providers = struct {
    pub var github = Provider{
        .id = "github",
        .auth_url = "https://github.com/login/oauth/authorize",
        .token_url = "https://github.com/login/oauth/access_token",
        .user_url = "https://api.github.com/user",
        .scope = "read:user",
        .name_prop = "login",
        .name_prefix = "@",
    };
    pub var google = Provider{
        .id = "google",
        .auth_url = "https://accounts.google.com/o/oauth2/v2/auth",
        //.token_url = "https://www.googleapis.com/oauth2/v4/token",
        .token_url = "https://oauth2.googleapis.com/token",
        .user_url = "https://www.googleapis.com/oauth2/v3/userinfo",
        .scope = "email profile",
        .name_prop = "name",
    };
};

pub const UserInfo = struct {
    email: ?[]const u8 = null,
    login: ?[]const u8 = null,
    name: ?[]const u8 = null,
};

pub const TokenInfo = struct {
    access_token: []const u8,
    token_type: []const u8,
};

pub fn providerById(name: string) !?Provider {
    inline for (comptime std.meta.declarations(providers)) |item| {
        const p = @field(providers, item.name);
        if (std.mem.eql(u8, p.id, name)) {
            return p;
        }
    }
    return null;
}

pub const OauthSettings = struct {
    success_url: []const u8,
    callback_url: []const u8,
};

pub fn OauthProvider(comptime T: type) type {
    comptime std.debug.assert(@hasDecl(T, "saveInfo"));

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        client: Client,
        success_url: []const u8,
        callback_url: []const u8,

        pub fn init(allocator: std.mem.Allocator, client: Client, settings: OauthSettings) !Self {
            return .{
                .allocator = allocator,
                .client = client,
                .success_url = settings.success_url,
                .callback_url = settings.callback_url,
            };
        }

        pub fn deinit(_: *const Self) void {}

        pub fn redirect(self: *const Self, r: *const zap.SimpleRequest, state: []const u8) !void {
            std.debug.print("oauth2.redirect: {s} got called\n", .{self.client.provider.id});
            const provider = self.client.provider;
            var params = Params.init(self.allocator);
            defer params.deinit();
            try params.add("client_id", self.client.id);
            var redirect_uri = try std.fmt.allocPrint(self.allocator, "http://localhost:3000{s}", .{self.callback_url});
            defer self.allocator.free(redirect_uri);
            try params.add("redirect_uri", redirect_uri);
            try params.add("scope", provider.scope);
            if (std.mem.eql(u8, self.client.provider.id, "google")) {
                try params.add("access_type", "offline");
                try params.add("response_type", "code");
            } else if (std.mem.eql(u8, self.client.provider.id, "github")) {
                try params.add("allow_signup", "yes");
            }
            try params.add("state", state);
            var output = try params.encode();
            defer self.allocator.free(output);
            const auth_url = try std.mem.join(self.allocator, "?", &.{ provider.auth_url, output });
            defer self.allocator.free(auth_url);
            try r.redirectTo(auth_url, .found);
        }

        pub fn callback(self: *const Self, r: *const zap.SimpleRequest) !void {
            std.debug.print("oauth2.callback: {s} got called\n", .{self.client.provider.id});
            r.parseQuery();

            if (r.getParamStr("state", self.allocator, false)) |maybe_state| {
                if (maybe_state) |*state| {
                    defer state.deinit();
                    std.debug.print("oauth2.callback: state:{s}\n", .{state.str});
                    if (r.getParamStr("code", self.allocator, false)) |maybe_code| {
                        if (maybe_code) |*code| {
                            defer code.deinit();
                            std.debug.print("oauth2.callback: code:{s}\n", .{code.str});

                            const token = try self.getTokenInfo(code.str);
                            defer self.allocator.free(token.access_token);
                            defer self.allocator.free(token.token_type);
                            std.debug.print("oauth2.callback: got access token:{s}\n", .{token.access_token});

                            const user = try self.getUserInfo(token);
                            if (user.email) |email| {
                                std.debug.print("oauth2.callback: got user info:{s}\n", .{email});
                            } else {
                                std.debug.print("oauth2.callback: got user info:{s}\n", .{user.login.?});
                            }

                            std.debug.print("oauth2.callback: calling saveInfo with state {s}:\n", .{state.str});
                            try T.saveInfo(self.allocator, r, self.client.provider.id, state.str, user);
                        }
                    } else |err| {
                        std.debug.print("oauth2.callback: getParamStr(state) failed: {}", .{err});
                    }
                }
            } else |err| {
                std.debug.print("oauth2.callback: getParamStr(code) failed: {}", .{err});
            }
            try r.redirectTo(self.success_url, .found);
        }

        fn getTokenInfo(self: *const Self, code: []const u8) !TokenInfo {
            std.debug.print("oauth2.callback: getting token info\n", .{});
            var client = std.http.Client{
                .allocator = self.allocator,
            };
            defer client.deinit();

            // setup request parameters
            var params = Params.init(self.allocator);
            defer params.deinit();
            try params.add("code", code);
            try params.add("client_id", self.client.id);
            try params.add("client_secret", self.client.secret);
            var redirect_uri = try std.fmt.allocPrint(self.allocator, "http://localhost:3000{s}", .{self.callback_url});
            defer self.allocator.free(redirect_uri);
            try params.add("redirect_uri", redirect_uri);
            if (std.mem.eql(u8, self.client.provider.id, "google")) {
                try params.add("grant_type", "authorization_code");
            }
            var output = try params.encode();
            defer self.allocator.free(output);
            std.debug.print("oauth2.token: params:{s}\n", .{output});

            var uri = try std.Uri.parse(self.client.provider.token_url);

            var headers = std.http.Headers{
                .allocator = self.allocator,
            };
            defer headers.deinit();

            try headers.append("Content-Type", "application/x-www-form-urlencoded");
            try headers.append("Accept", "application/json");
            //const length_header = try std.fmt.allocPrint(self.allocator, "{d}", .{output.len});
            //defer self.allocator.free(length_header);
            //try headers.append("Content-Length", length_header);

            // make the connection and set up the request
            var req: std.http.Client.Request = undefined;
            if (std.mem.eql(u8, self.client.provider.id, "google")) {
                req = try client.request(.POST, uri, headers, .{ .version = std.http.Version.@"HTTP/1.0" });
            } else if (std.mem.eql(u8, self.client.provider.id, "github")) {
                req = try client.request(.POST, uri, headers, .{});
            } else unreachable;
            defer req.deinit();

            //req.transfer_encoding = std.http.Client.RequestTransfer{ .content_length = output.len };
            req.transfer_encoding = .{ .content_length = output.len };

            std.debug.print("oauth2.token: starting request\n", .{});
            try req.start();

            // write the params in the body
            std.debug.print("oauth2.token: writing request\n", .{});
            _ = try req.writer().writeAll(output);

            std.debug.print("oauth2.token: finishing request\n", .{});
            try req.finish();

            // wait for server to send us a response
            std.debug.print("oauth2.token: waiting for response\n", .{});
            try req.wait();

            std.debug.print("oauth2.token: got reply\n", .{});
            // read the entire response body
            const body = req.reader().readAllAlloc(self.allocator, 1024 * 2) catch unreachable;
            defer self.allocator.free(body);

            std.debug.print("oauth2.token: body:{s}\n", .{body});

            const token = try std.json.parseFromSlice(TokenInfo, self.allocator, body, .{
                .ignore_unknown_fields = true,
            });
            defer std.json.parseFree(TokenInfo, self.allocator, token);

            return .{
                .access_token = try self.allocator.dupe(u8, token.access_token),
                .token_type = try self.allocator.dupe(u8, token.token_type),
            };
        }

        fn getUserInfo(self: *const Self, token: TokenInfo) !UserInfo {
            std.debug.print("oauth2.user: getting user info\n", .{});
            var client = std.http.Client{
                .allocator = self.allocator,
            };
            defer client.deinit();

            var uri = try std.Uri.parse(self.client.provider.user_url);

            var headers = std.http.Headers{
                .allocator = self.allocator,
            };
            defer headers.deinit();

            var auth_header = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{token.access_token});
            defer self.allocator.free(auth_header);
            std.debug.print("oauth2.callback: auth header:{s}\n", .{auth_header});
            try headers.append("Authorization", auth_header);
            try headers.append("Accept", "application/json");

            var req: std.http.Client.Request = undefined;
            if (std.mem.eql(u8, self.client.provider.id, "google")) {
                req = try client.request(.GET, uri, headers, .{ .version = std.http.Version.@"HTTP/1.0" });
            } else if (std.mem.eql(u8, self.client.provider.id, "github")) {
                req = try client.request(.GET, uri, headers, .{});
            } else unreachable;
            defer req.deinit();

            std.debug.print("oauth2.user: starting userinfo request\n", .{});
            try req.start();

            std.debug.print("oauth2.user: waiting for userinfo\n", .{});
            try req.wait();

            const body = req.reader().readAllAlloc(self.allocator, 1024 * 2) catch unreachable;
            defer self.allocator.free(body);
            std.debug.print("oauth2.user: got userinfo:{s}\n", .{body});
            const user = try std.json.parseFromSlice(UserInfo, self.allocator, body, .{
                .ignore_unknown_fields = true,
            });
            defer std.json.parseFree(UserInfo, self.allocator, user);

            return .{
                .email = if (user.email) |v| try self.allocator.dupe(u8, v) else null,
                .login = if (user.login) |v| try self.allocator.dupe(u8, v) else null,
                .name = if (user.name) |v| try self.allocator.dupe(u8, v) else null,
            };
        }
    };
}
