pub const UserDetails = struct {
    authzid: []const u8,
    authcid: []const u8,
    passwd: []const u8,

    pub fn deinit(self: *const UserDetails, allocator: std.mem.Allocator) void {
        allocator.free(self.authzid);
        allocator.free(self.authcid);
        allocator.free(self.passwd);
    }
};

pub fn plain_read_details(allocator: std.mem.Allocator, input_b64: []const u8) !UserDetails {
    const decoder: std.base64.Base64Decoder = .init(std.base64.standard_alphabet_chars, '=');
    const input_len = try decoder.calcSizeForSlice(input_b64);
    const input = try allocator.alloc(u8, input_len);
    defer allocator.free(input);

    try decoder.decode(input, input_b64);

    var iter: std.unicode.Utf8Iterator = .{ .bytes = input, .i = 0 };

    var authzid_start: usize = 0;
    var authzid_end: usize = 0;
    while (iter.nextCodepointSlice()) |c| {
        if (c.len == 1 and c[0] == 0) break; // UTF-8 null
        authzid_end += c.len;
    }

    const authcid_start: usize = authzid_end + 1;
    var authcid_end: usize = authzid_end + 1;
    while (iter.nextCodepointSlice()) |c| {
        if (c.len == 1 and c[0] == 0) break; // UTF-8 null
        authcid_end += c.len;
    }

    const passwd_start: usize = authcid_end + 1;
    var passwd_end: usize = authcid_end + 1;
    while (iter.nextCodepointSlice()) |c| {
        passwd_end += c.len;
    }

    // If the authorization id is empty, use the authentication id as the authorization id
    if (input[authzid_start..authzid_end].len == 0) {
        authzid_start = authcid_start;
        authzid_end = authcid_end;
    }

    return UserDetails{
        .authzid = try allocator.dupe(u8, input[authzid_start..authzid_end]),
        .authcid = try allocator.dupe(u8, input[authcid_start..authcid_end]),
        .passwd = try allocator.dupe(u8, input[passwd_start..passwd_end]),
    };
}

pub fn plain(allocator: std.mem.Allocator, user: UserDetails) bool {
    if (!std.mem.eql(u8, user.authzid, user.authcid)) {
        std.debug.print("authzid and authcid differ\n", .{});
        return false;
    }
    return user_store.check_passwd(allocator, user.authcid, user.passwd) catch false;
}


const std = @import("std");

const user_store = @import("user_store.zig");
