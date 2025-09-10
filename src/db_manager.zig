var db_handle: ?*sqlite.DB = null;

const DBError = error {
    NotInitialized,
};

pub const UsersTable = Table("users", &[_]TableColumn{
    .{ .name = "id", .db_type = "INTEGER PRIMARY KEY AUTOINCREMENT" },
    .{ .name = "username", .db_type = "TEXT NOT NULL UNIQUE" },
    .{ .name = "password_hash", .db_type = "TEXT NOT NULL" },
}, null);

pub const MailboxesTable = Table("mailboxes", &[_]TableColumn{
    .{ .name = "id", .db_type = "INTEGER PRIMARY KEY AUTOINCREMENT" },
    .{ .name = "name", .db_type = "TEXT NOT NULL" },
    .{ .name = "uid_validity", .db_type = "INTEGER NOT NULL DEFAULT 1" },
}, &[_][]const u8{
    "UNIQUE(name,owner)",
});

pub const MessagesTable = Table("messages", &[_]TableColumn{
    .{ .name = "mailbox_id", .db_type = "INTEGER NOT NULL" },
    .{ .name = "uid", .db_type = "INTEGER NOT NULL" },
}, &[_][]const u8 {
    "PRIMARY KEY (mailbox_id,uid)",
    "FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id)"
});


pub fn init() !void {
    if (db_handle == null) {
        db_handle = try sqlite.open("./talaria.db");

        try UsersTable.create();
        try MailboxesTable.create();
    }
}

pub fn deinit() void {
    if (db_handle != null) {
        sqlite.close(db_handle.?);
        db_handle = null;
    }
}


const TableColumn = struct {
    name: [:0]const u8, // std.builtin.Type.EnumField requires a null-terminated string
    db_type: []const u8,
};


fn Table(table_name: []const u8, table_columns: []const TableColumn, table_constraints: ?[]const []const u8) type {
    comptime var column_fields: [table_columns.len]std.builtin.Type.EnumField = undefined;
    inline for (table_columns, 0..) |column, i| {
        column_fields[i] = std.builtin.Type.EnumField{ .name = column.name, .value = i };
    }

    const column_type_info = std.builtin.Type.Enum{
        .tag_type = @Type(.{ .int = std.builtin.Type.Int{ .bits = std.math.log2(table_columns.len) + 1, .signedness = .unsigned } }),
        .fields = &column_fields,
        .decls = &[0]std.builtin.Type.Declaration{},
        .is_exhaustive = true,
    };
    const column_type = @Type(.{ .@"enum" = column_type_info });

    return struct {
        const Column = column_type;

        pub fn create() !void {
            comptime var query_str: []const u8 = "CREATE TABLE IF NOT EXISTS " ++ table_name ++ " (";

            comptime var first = true;
            inline for (table_columns) |column| {
                if (!first) {
                    query_str = query_str ++ ", ";
                }
                query_str = query_str ++ column.name ++ " " ++ column.db_type;
                first = false;
            }

            if (table_constraints) |constraints| {
                inline for(constraints) |constraint| {
                    query_str = query_str ++ ", " ++ constraint;
                }
            }
            query_str = query_str ++ ")";

            if (db_handle == null) {
                return DBError.NotInitialized;
            }
            try sqlite.exec(db_handle.?, query_str, .{});
        }

        pub fn select(comptime n: usize, comptime columns: [n]Column, comptime where: ?[]const u8, args: anytype) !sqlite.Result {
            comptime var query_str: []const u8 = "SELECT ";

            if (n == 0) {
                query_str = query_str ++ "* ";
            } else {
                comptime var first = true;
                inline for (columns) |col| {
                    if (!first) {
                        query_str = query_str ++ ", ";
                    }
                    query_str = query_str ++ @tagName(col);
                    first = false;
                }
            }

            query_str = query_str ++ " FROM " ++ table_name;
            if (where) |where_clause| {
                query_str = query_str ++ " WHERE " ++ where_clause;
            }

            if (db_handle == null) {
                return DBError.NotInitialized;
            }
            return sqlite.query(db_handle.?, query_str, args);
        }

        pub fn insert(comptime n: usize, comptime columns: [n]Column, values: anytype) !i64 {
            comptime var query_str: []const u8 = "INSERT INTO " ++ table_name ++ "(";

            comptime var first = true;
            inline for (columns) |col| {
                if (!first) {
                    query_str = query_str ++ ", ";
                }
                query_str = query_str ++ @tagName(col);
                first = false;
            }

            query_str = query_str ++ ") values(";
            first = true;
            inline for (columns) |_| {
                if (!first) {
                    query_str = query_str ++ ", ";
                }
                query_str = query_str ++ "?";
                first = false;
            }
            query_str = query_str ++ ")";

            if (db_handle == null) {
                return DBError.NotInitialized;
            }
            try sqlite.exec(db_handle.?, query_str, values);
            return sqlite.last_insert_id(db_handle.?);
        }
    };
}


const std = @import("std");

const sqlite = @import("sqlite.zig");
