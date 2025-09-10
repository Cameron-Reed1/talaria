pub var shut_down: std.atomic.Value(bool) = .init(false);


fn exit_signal(_: i32) callconv(.C) void {
    shut_down.store(true, .release);
}


pub fn main() !void {
    var dbga = std.heap.DebugAllocator(.{}){};
    defer {
        if (dbga.deinit() == .leak) {
            std.debug.print("Memory was leaked D:\n", .{});
        }
    }
    const allocator = dbga.allocator();

    const exit_handler = std.posix.Sigaction{
        .handler = .{ .handler = exit_signal },
        .mask = std.posix.empty_sigset,
        .flags = std.posix.SA.RESETHAND,
    };
    std.posix.sigaction(std.posix.SIG.INT, &exit_handler, null);

    try db_manager.init();
    defer db_manager.deinit();

    // var r: [1]u8 = undefined;
    // try std.posix.getrandom(&r);
    // print_struct(.{ .rand = r[0], .first = 2, .second = 3, .name = "poppy", .popcorn = true });
    // try std.posix.getrandom(&r);
    // print_struct(.{ .rand = r[0], .first = 2, .second = 3, .name = "poppy", .popcorn = true });
    //
    // if (true) return;

    // Load server certificate key pair
    const cert_dir = try std.fs.cwd().openDir("/etc/letsencrypt/live/", .{});
    var auth = try tls.config.CertKeyPair.fromFilePath(allocator, cert_dir, "mail-test/fullchain.pem", "mail-test/privkey.pem");
    defer auth.deinit(allocator);

    const hostname = "mail-test.cam123.dev";
    _ = hostname;

    var imap_server = imap.Server{ .address = [4]u8{127, 0, 0, 1}, .auth = &auth };
    var submission_server = smtp.Server{ .address = [4]u8{127, 0, 0, 1}, .auth = &auth };

    const imap_thread = try std.Thread.spawn(.{}, imap.Server.start, .{ &imap_server, allocator });
    const submission_thread = try std.Thread.spawn(.{}, smtp.Server.start, .{ &submission_server, allocator });

    while (!shut_down.load(.acquire)) {
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    std.debug.print("\nShutting down\n", .{});

    imap_thread.join();
    submission_thread.join();

    std.debug.print("Goodbye o/\n", .{});
}

pub fn print_struct(s: anytype) void {
    const fields = @typeInfo(@TypeOf(s)).@"struct".fields;
    inline for (fields) |field| {
        const fmt = comptime if (is_str(field.type)) "{s}: {s} = {s}\n" else "{s}: {s} = {any}\n";
        std.debug.print(fmt, .{ field.name, @typeName(field.type), @field(s, field.name) });
    }
}

fn is_str(T: type) bool {
    const type_info = @typeInfo(T);
    if (type_info != .pointer) return false;
    if (type_info.pointer.child == u8 and type_info.pointer.size != .one) return true;

    const child_info = @typeInfo(type_info.pointer.child);
    if (child_info != .array) return false;
    return child_info.array.child == u8;
}


test "import_tests" {
    // Just need to reference the imports for files that have tests to get them to run with `zig build test`
    _ = imap;
    _ = smtp;
    _ = sqlite;
}


const std = @import("std");
const tls = @import("tls");

const imap = @import("imap.zig");
const smtp = @import("smtp_submission.zig");
const sqlite = @import("sqlite.zig");
const user_store = @import("user_store.zig");
const db_manager = @import("db_manager.zig");
