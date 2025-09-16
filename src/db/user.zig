const MailboxesTable = sqlite.Table("mailboxes", &[_]sqlite.TableColumn{
    .{ .name = "id", .db_type = "INTEGER PRIMARY KEY AUTOINCREMENT" },
    .{ .name = "name", .db_type = "TEXT NOT NULL UNIQUE" },
    .{ .name = "uid_validity", .db_type = "INTEGER NOT NULL DEFAULT 1" },
}, null);


const MessagesTable = sqlite.Table("messages", &[_]sqlite.TableColumn{
    .{ .name = "mailbox_id", .db_type = "INTEGER NOT NULL" },
    .{ .name = "uid", .db_type = "INTEGER NOT NULL" },
}, &[_][]const u8 {
    "PRIMARY KEY (mailbox_id,uid)",
    "FOREIGN KEY (mailbox_id) REFERENCES mailboxes (id)"
});



pub const UserDB = struct {
    mailboxes: MailboxesTable,
    messages: MessagesTable,

    fn init(db_handle: *sqlite.DB) !UserDB {
        const mb_table = MailboxesTable{ .db_handle = db_handle };
        try mb_table.create();

        const msg_table = MessagesTable{ .db_handle = db_handle };
        try msg_table.create();

        return .{
            .mailboxes = mb_table,
            .messages = msg_table,
        };
    }

    pub fn close(self: *const UserDB) void {
        sqlite.close(self.mailboxes.db_handle);
    }
};



fn username_to_id(username: []const u8) !i64 {
    var res = try main_db.UsersTable.select(1, .{ .id }, "WHERE username=?", .{ username });
    defer res.close();

    if (!try res.next()) return error.TEMP;
    const id = res.get_int(0);
    if (try res.next()) return error.TEMP;

    return id;
}

fn id_to_db_name(allocator: std.mem.Allocator, id: i64) ![:0]const u8 {
    return try std.fmt.allocPrintSentinel(allocator, "{s}/{d}.db", .{ cfg.values.user_db_path, id }, 0);
}


pub fn get(allocator: std.mem.Allocator, username: []const u8) !UserDB {
    const id = try username_to_id(username);
    return try get_id(allocator, id);
}

pub fn get_id(allocator: std.mem.Allocator, id: i64) !UserDB {
    std.fs.cwd().makeDir(cfg.values.user_db_path) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };

    const file = try id_to_db_name(allocator, id);
    defer allocator.free(file);
    const db_handle = try sqlite.open(file);

    return try UserDB.init(db_handle);
}



const std = @import("std");
const cfg = @import("config");

const main_db = @import("main.zig");
const sqlite = @import("sqlite.zig");
