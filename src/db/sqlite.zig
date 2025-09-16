const SqliteError = error {
    FailedToOpen,
    FailedToBindArgument,
    FailedToPrepareStatement,
};



pub const DB = c.sqlite3;


pub const TableColumn = struct {
    name: [:0]const u8, // std.builtin.Type.EnumField requires a null-terminated string
    db_type: []const u8,
};


pub fn Table(table_name: []const u8, table_columns: []const TableColumn, table_constraints: ?[]const []const u8) type {
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
        const Self = @This();

        db_handle: *DB = undefined,

        pub fn create(self: *const Self) !void {
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

            try exec(self.db_handle, query_str, .{});
        }

        pub fn select(self: *const Self, comptime n: usize, comptime columns: [n]Column, comptime extra: ?[]const u8, args: anytype) !Result {
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
            if (extra) |ex| {
                query_str = query_str ++ " " ++ ex;
            }

            return query(self.db_handle, query_str, args);
        }

        pub fn insert(self: *const Self, comptime n: usize, comptime columns: [n]Column, values: anytype) !i64 {
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

            try exec(self.db_handle, query_str, values);
            return last_insert_id(self.db_handle);
        }
    };
}



pub const Result = struct {
    statement: *c.sqlite3_stmt,

    pub fn next(self: Result) !bool {
        const res = c.sqlite3_step(self.statement);
        switch (res) {
            c.SQLITE_DONE => return false,
            c.SQLITE_ROW => return true,
            else => return error.Hi,
        }
    }

    pub fn column_count(self: Result) i32 {
        return c.sqlite3_column_count(self.statement);
    }

    pub fn get_int(self: Result, col_idx: i32) i64 {
        return c.sqlite3_column_int64(self.statement, col_idx);
    }

    pub fn get_double(self: Result, col_idx: i32) f64 {
        return c.sqlite3_column_double(self.statement, col_idx);
    }

    pub fn get_text(self: Result, col_idx: i32) ?[]const u8 {
        if (c.sqlite3_column_text(self.statement, col_idx)) |text| {
            return std.mem.span(text);
        } else {
            return null;
        }
    }

    pub fn close(self: Result) void {
        _ = c.sqlite3_finalize(self.statement);
    }
};

pub fn open(file: [:0]const u8) SqliteError!*c.sqlite3 {
    var db: ?*c.sqlite3 = null;

    const ret = c.sqlite3_open(file, &db);
    if (db == null) {
        return SqliteError.FailedToOpen;
    }

    if (ret != c.SQLITE_OK) {
        _ = c.sqlite3_close(db);
        return SqliteError.FailedToOpen;
    }

    return db.?;
}

pub fn close(db: *DB) void {
    _ = c.sqlite3_close(db);
}

pub fn last_insert_id(db: *DB) i64 {
    return c.sqlite3_last_insert_rowid(db);
}

pub fn exec(db: *DB, stmt: []const u8, args: anytype) !void {
    const result = try query(db, stmt, args);
    defer result.close();
    while (try result.next()) { }
}

pub fn query(db: *c.sqlite3, stmt: []const u8, args: anytype) !Result {
    var statement: ?*c.sqlite3_stmt = null;
    var res = c.sqlite3_prepare_v2(db, stmt.ptr, @intCast(stmt.len), &statement, null);
    if (statement == null or res != c.SQLITE_OK) {
        std.debug.print("Error code: {}\n", .{ res });
        _ = c.sqlite3_finalize(statement);
        return SqliteError.FailedToPrepareStatement;
    }

    const argsTypeInfo = @typeInfo(@TypeOf(args));
    if (argsTypeInfo != .@"struct") {
        @compileError("expected tuple or struct argument, found " ++ @typeName(@TypeOf(args)));
    }

    const fields_info = argsTypeInfo.@"struct".fields;
    inline for (fields_info, 1..) |field, i| {
        res = bind(statement.?, i, @field(args, field.name));
        if (res != c.SQLITE_OK) {
            return SqliteError.FailedToBindArgument;
        }
    }

    return .{ .statement = statement.? };
}

fn bind(statement: *c.sqlite3_stmt, index: u32, value: anytype) c_int {
    const typeInfo = @typeInfo(@TypeOf(value));
    switch (typeInfo) {
        .int => {
            if (typeInfo.int.bits <= 32) {
                return c.sqlite3_bind_int(statement, @intCast(index), value);
            } else {
                return c.sqlite3_bind_int64(statement, @intCast(index), value);
            }
        },
        .float => {
            return c.sqlite3_bind_double(statement, @intCast(index), value);
        },
        .null => {
            return c.sqlite3_bind_null(statement, @intCast(index));
        },
        .pointer => {
            if (typeInfo.pointer.child == u8 or @typeInfo(typeInfo.pointer.child) == .array and @typeInfo(typeInfo.pointer.child).array.child == u8) {
                const text_value: []const u8 = @ptrCast(value);
                return c.sqlite3_bind_text(statement, @intCast(index), text_value.ptr, @intCast(text_value.len), c.SQLITE_STATIC);
            } else {
                @compileError("Cannot bind type of " ++ @typeName(@TypeOf(value)) ++ " to sqlite statement");
            }
        },
        .optional => {
            if (value == null) {
                return bind(statement, index, null);
            } else {
                return bind(statement, index, value.?);
            }
        },
        else => @compileError("Cannot bind type of " ++ @typeName(@TypeOf(value)) ++ " to sqlite statement"),
    }
}


const std = @import("std");

const c = @cImport(
    @cInclude("sqlite3.h")
);
