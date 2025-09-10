pub fn check_passwd(allocator: std.mem.Allocator, username: []const u8, passwd: []const u8) !bool {
    std.debug.print("Checking password [{s} (len={})] against username [{s} (len={})]\n", .{ passwd, passwd.len, username, username.len });

    const passwd_hash = try get_passwd_hash(allocator, username);
    if (passwd_hash == null) return false;
    defer allocator.free(passwd_hash.?);

    argon2.strVerify(passwd_hash.?, passwd, .{ .allocator = allocator }) catch return false;
    return true;
}

pub fn create_user(allocator: std.mem.Allocator, username: []const u8, passwd: []const u8) !i64 {
    var buf: [128]u8 = undefined;
    const hash = try argon2.strHash(passwd, .{ .allocator = allocator, .params = .{ .t = 3, .m = 32, .p = 4 } }, &buf);

    return try db_manager.UsersTable.insert(2, .{ .username, .password_hash }, .{ username, hash });
}

fn get_passwd_hash(allocator: std.mem.Allocator, username: []const u8) !?[]const u8 {
    const result = try db_manager.UsersTable.select(1, .{ .password_hash }, "username=?", .{ username });
    defer result.close();

    if (!try result.next()) return null;
    const hash = if (result.get_text(0)) |pw_hash| try allocator.dupe(u8, pw_hash) else return null;

    if (try result.next()) {
        allocator.free(hash);
        return null; // There should have only been one result
    }

    return hash;
}


const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;

const db_manager = @import("db_manager.zig");
const sqlite = @import("sqlite.zig");
