pub const MailboxError = error {
    DoesNotExist,
    BadDBState,
};

pub fn create(name: []const u8) !i32 {
    return db_manager.MailboxesTable.insert(1, .{ .name }, .{ name });
}

pub fn get(name: []const u8) !Mailbox {
    var id: i64 = 0;
    var uid_validity: u32 = 0;
    var msg_count: u32 = 0;
    var next_uid: u32 = 0;

    {
        const res = try db_manager.MailboxesTable.select(2, .{ .id, .uid_validity }, "name=?", .{ name });
        defer res.close();

        if (!try res.next()) return MailboxError.DoesNotExist;
        id = res.get_int(0);
        uid_validity = @intCast(res.get_int(1));
        if (try res.next()) return MailboxError.BadDBState; // There should only be one result
    }

    {
        const res = try db_manager.MessagesTable.select(1, .{ .uid }, "mailbox_id=? ORDER BY uid", .{ id });

        while (try res.next()) {
            msg_count += 1;
            next_uid = @intCast(res.get_int(0));
        }
    }

    return Mailbox{ .id = id, .name = name, .uid_validity = uid_validity, .next_uid = next_uid + 1, .msg_count = msg_count, .read_only = false };
}

pub const Mailbox = struct {
    id: i64,
    name: []const u8,
    uid_validity: u32,
    next_uid: u32,
    msg_count: u32,
    read_only: bool,
};


const db_manager = @import("db_manager.zig");
