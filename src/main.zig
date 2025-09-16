pub var shut_down: std.atomic.Value(bool) = .init(false);


fn exit_signal(_: i32) callconv(.c) void {
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
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.RESETHAND,
    };
    std.posix.sigaction(std.posix.SIG.INT, &exit_handler, null);

    try db.init();
    defer db.deinit();

    // Load server certificate key pair
    const cert_dir = try std.fs.cwd().openDir("/etc/letsencrypt/live/", .{});
    var auth = try tls.config.CertKeyPair.fromFilePath(allocator, cert_dir, "mail-test/fullchain.pem", "mail-test/privkey.pem");
    defer auth.deinit(allocator);

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


test "import_tests" {
    // Just need to reference the imports for files that have tests to get them to run with `zig build test`
    _ = imap;
    _ = smtp;
    _ = @import("db/sqlite.zig");
}


const std = @import("std");
const tls = @import("tls");

const imap = @import("imap.zig");
const smtp = @import("smtp_submission.zig");
const user_store = @import("user_store.zig");
const db = @import("db/main.zig");
