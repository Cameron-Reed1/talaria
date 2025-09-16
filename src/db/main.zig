pub var DBInfoTable = sqlite.Table("info", &[_]sqlite.TableColumn{
    .{ .name = "id", .db_type = "INTEGER PRIMARY KEY AUTOINCREMENT" },
    .{ .name = "schema_version", .db_type = "INTEGER NOT NULL" },
    .{ .name = "upgraded_from", .db_type = "INTEGER" },
    .{ .name = "time", .db_type = "TEXT NOT NULL" },
}, null){ .db_handle = undefined };

pub var UsersTable = sqlite.Table("users", &[_]sqlite.TableColumn{
    .{ .name = "id", .db_type = "INTEGER PRIMARY KEY AUTOINCREMENT" },
    .{ .name = "username", .db_type = "TEXT NOT NULL UNIQUE" },
    .{ .name = "password_hash", .db_type = "TEXT NOT NULL" },
}, null){ .db_handle = undefined };


var db_handle: ?*sqlite.DB = null;
const schema_version: i64 = -1;

const logger = std.log.scoped(.main_db);


pub fn init() !void {
    if (db_handle == null) {
        db_handle = try sqlite.open("./talaria.db");

        DBInfoTable.db_handle = db_handle.?;
        UsersTable.db_handle = db_handle.?;

        const version: ?i64 = blk: {
            { // Check if info table exists
                var res = try sqlite.query(db_handle.?, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='info';", .{});
                defer res.close();

                if (!try res.next()) break :blk null;
                if (res.get_int(0) == 0) break :blk null;
            }

            { // If id does, attempt to grab the schema version
                var res = try DBInfoTable.select(1, .{ .schema_version }, "ORDER BY id DESC LIMIT 1", .{});
                defer res.close();

                if (!try res.next()) break :blk null;
                break :blk res.get_int(0);
            }
        };

        if (version == null) {
            logger.warn("Failed to find schema version in db", .{});

            try UsersTable.create();
            try DBInfoTable.create();
            try add_schema_version(null);
        } else if (version.? < schema_version) {
            logger.info("Schema version {d} found in db is older than the current version {d}. Attempting upgrade", .{ version.?, schema_version });

            try upgrade_schema(version.?);
        } else if (version.? > schema_version) {
            logger.err("Schema version {d} found in db is newer than the current version {d}. Aborting", .{ version.?, schema_version });
            return error.SchemaTooNew;
        }
    }
}

fn upgrade_schema(from: i64) !void {
    try add_schema_version(from);
}

fn add_schema_version(upgraded_from: ?i64) !void {
    _ = try DBInfoTable.insert(3, .{ .schema_version, .upgraded_from, .time }, .{ schema_version, upgraded_from, std.time.timestamp() });
}

pub fn deinit() void {
    if (db_handle != null) {
        sqlite.close(db_handle.?);
        db_handle = null;
    }
}


const std = @import("std");
const builtin = @import("builtin");

const sqlite = @import("sqlite.zig");
