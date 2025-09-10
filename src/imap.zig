const command_handler = *const fn(conn: *Connection, cmd: *const Command) anyerror!void;
const handlers: std.StaticStringMap(command_handler) = .initComptime(.{
    .{ "NOOP", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_noop); } }.handle },
    .{ "LOGOUT", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_logout); } }.handle },
    .{ "CAPABILITY", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_capability); } }.handle },
    .{ "STARTTLS", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_starttls); } }.handle },
    .{ "AUTHENTICATE", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_authenticate); } }.handle },
    .{ "LOGIN", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_login); } }.handle },
    .{ "ENABLE", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_enable); } }.handle },
    .{ "SELECT", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_select); } }.handle },
    .{ "EXAMINE", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_examine); } }.handle },
});


const logger = std.log.scoped(.imap);


const Connection = struct {
    const State = enum {
        not_authenticated,
        authenticated,
        selected,
        logout,
    };

    const BYE = Response{ .tag = null, .type = .bye, .text = "" };

    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    reader: std.io.AnyReader,
    writer: std.io.AnyWriter,
    logged_out: bool,
    user: ?[]const u8,
    mailbox: ?mailbox.Mailbox,
    read_buf: [8192]u8,

    fn state(self: *const Connection) State {
        if (self.mailbox != null) {
            return .selected;
        } else if (self.user != null) {
            return .authenticated;
        } else if (!self.logged_out) {
            return .not_authenticated;
        }
        return .logout;
    }

    fn read_command(self: *Connection) !Command {
        var pollfd = [1]std.posix.pollfd{
            .{
                .fd = self.fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }
        };
        if (try std.posix.poll(&pollfd, 100) == 0) return error.Timeout;

        const tag = try self.reader.readUntilDelimiter(&self.read_buf, ' ');
        var input = self.reader.readUntilDelimiter(self.read_buf[tag.len..self.read_buf.len], '\n') catch |err| {
            if (err == error.StreamTooLong) {
                try self.send(.{ .tag = tag, .type = .bad, .text = "Command too long" });
            }
            return err;
        };

        if (input[input.len - 1] != '\r') {
            logger.debug("Command doesn't end with CRLF", .{});
        } else {
            input = input[0..input.len - 1];
        }

        const cmd = try Command.parse(self.allocator, tag, input);
        return cmd;
    }

    fn unselect_mailbox(self: *Connection) !void {
        if (self.state() == .selected) {
            self.mailbox = null;

            try self.send(.{ .tag = null, .type = .ok, .text = "[CLOSED] Previous mailbox is now closed" });
        }
    }

    fn select_mailbox(self: *Connection, allocator: std.mem.Allocator, name: []const u8) !void {
        if (self.state() == .selected) {
            try self.unselect_mailbox();
        }

        self.mailbox = try mailbox.get(name);

        if (self.mailbox) |mb| {
            try self.send(Response{ .tag = null, .type = .flags, .text = "" });
            const count_str = try std.fmt.allocPrint(allocator, "{}", .{ mb.msg_count });
            defer allocator.free(count_str);
            try self.send(Response{ .tag = null, .type = .exists, .text = count_str });
        }
    }

    fn send(self: *Connection, msg: Response) !void {
        const tag = if (msg.tag) |t| t else "*";
        _ = try self.writer.writeAll(tag);
        _ = try self.writer.writeAll(" ");

        if (msg.type == .exists) {
            logger.debug("{s} {s} {s}", .{ tag, msg.text, msg.type.str() });
            _ = try self.writer.writeAll(msg.text);
            _ = try self.writer.writeAll(" ");
            _ = try self.writer.writeAll(msg.type.str());
        } else {
            logger.debug("{s} {s} {s}", .{ tag, msg.type.str(), msg.text });
            _ = try self.writer.writeAll(msg.type.str());
            _ = try self.writer.writeAll(" ");
            _ = try self.writer.writeAll(msg.text);
        }
        _ = try self.writer.writeAll("\r\n");
    }

    fn bye(self: *Connection) !void {
        try self.send(BYE);
    }
};


fn handle_noop(conn: *Connection, cmd: *const Command) !void {
    try conn.send(cmd.ok("NOOP completed"));
}


fn handle_logout(conn: *Connection, cmd: *const Command) !void {
    try conn.bye();
    conn.logged_out = true;

    if (conn.user) |user| {
        conn.user = null;
        conn.allocator.free(user);
    }

    try conn.send(cmd.ok("LOGOUT completed"));
}


fn handle_capability(conn: *Connection, cmd: *const Command) !void {
    const capabilities = "IMAP4rev2 AUTH=PLAIN";
    try conn.send(.{ .tag = null, .type = .capability, .text = capabilities });
    try conn.send(cmd.ok("CAPABILITY completed"));
}


fn handle_starttls(conn: *Connection, cmd: *const Command) !void {
    if (conn.state() != .not_authenticated) {
        try conn.send(cmd.bad("STARTTLS is only valid in the \"not authenticated\" state"));
        return;
    }

    // Currently only uses implicit tls port, so all connections are already using TLS
    try conn.send(cmd.bad("Connection is already using TLS"));
}


fn handle_authenticate(conn: *Connection, cmd: *const Command, method: []const u8, b64_details: []const u8) !void {
    if (conn.state() != .not_authenticated) {
        try conn.send(cmd.bad("AUTHENTICATE is only valid in the \"not authenticated\" state"));
        return;
    }

    std.debug.assert(std.mem.eql(u8, method, "PLAIN"));

    const user_details = try sasl.plain_read_details(conn.allocator, b64_details);
    defer user_details.deinit(conn.allocator);
    const success = sasl.plain(conn.allocator, user_details);

    if (success) {
        conn.user = try conn.allocator.dupe(u8, user_details.authzid);
        try conn.send(cmd.ok("AUTHENTICATE successful"));
    } else {
        try conn.send(cmd.no("AUTHENTICATE failed"));
    }
}


fn handle_login(conn: *Connection, cmd: *const Command, username: []const u8, password: []const u8) !void {
    if (conn.state() != .not_authenticated) {
        try conn.send(cmd.bad("LOGIN is only valid in the \"not authenticated\" state"));
        return;
    }

    const success = user_store.check_passwd(conn.allocator, username, password) catch false;

    if (success) {
        conn.user = try conn.allocator.dupe(u8, username);
        try conn.send(cmd.ok("LOGIN completed"));
    } else {
        try conn.send(cmd.no("LOGIN failed"));
    }
}


fn handle_enable(conn: *Connection, cmd: *const Command) !void {
    if (conn.state() != .authenticated) {
        try conn.send(cmd.bad("ENABLE is only valid in the \"authenticated\" state"));
        return;
    }

    // We don't support any extensions yet
    try conn.send(.{ .tag = null, .type = .enabled, .text = "" });
    try conn.send(cmd.ok("ENABLE completed"));
}


fn handle_select(conn: *Connection, cmd: *const Command, mb_name: []const u8) !void {
    if (conn.user == null) {
        try conn.send(cmd.bad("SELECT is not valid in current state"));
        return;
    }

    conn.select_mailbox(conn.allocator, mb_name) catch {
        try conn.send(cmd.no("Failed to select requested mailbox"));
        return;
    };

    try conn.send(cmd.ok("SELECT completed"));
}

fn handle_examine(conn: *Connection, cmd: *const Command, mb_name: []const u8) !void {
    if (conn.user == null) {
        try conn.send(cmd.bad("EXAMINE is not valid in current state"));
        return;
    }

    conn.select_mailbox(conn.allocator, mb_name) catch {
        try conn.send(cmd.no("Failed to select requested mailbox"));
        return;
    };

    if (conn.mailbox != null) {
        conn.mailbox.?.read_only = true;
    }
    try conn.send(cmd.ok("[READ-ONLY] EXAMINE completed"));
}


const Command = struct {
    tag: []const u8,
    cmd: []const u8,
    args: [][]const u8,

    fn parse(allocator: std.mem.Allocator, tag: []const u8, input_str: []const u8) !Command {
        var start: usize = 0;
        var end: usize = 0;

        // Read the command
        while (end < input_str.len and input_str[end] != ' ') {
            end += 1;
        }
        const cmd = try std.ascii.allocUpperString(allocator, input_str[start..end]);

        // Read the arguments
        var args: std.ArrayListUnmanaged([]const u8) = .empty;
        while (end < input_str.len) {
            end += 1; // Skip the space
            start = end;

            while (end < input_str.len and input_str[end] != ' ') {
                end += 1;
            }

            if (start != end) {
                try args.append(allocator, input_str[start..end]);
            }
        }

        return Command{
            .tag = tag,
            .cmd = cmd,
            .args = try args.toOwnedSlice(allocator),
        };
    }

    fn ok(self: *const Command, text: []const u8) Response {
        return .{ .tag = self.tag, .type = .ok, .text = text };
    }

    fn no(self: *const Command, text: []const u8) Response {
        return .{ .tag = self.tag, .type = .no, .text = text };
    }

    fn bad(self: *const Command, text: []const u8) Response {
        return .{ .tag = self.tag, .type = .bad, .text = text };
    }

    fn deinit(self: *const Command, allocator: std.mem.Allocator) void {
        allocator.free(self.cmd);
        allocator.free(self.args);
    }
};

const Response = struct {
    const Type = enum {
        ok,
        no,
        bad,
        bye,
        list,
        flags,
        exists,
        enabled,
        preauth,
        capability,

        fn str(self: Type) []const u8 {
            inline for(@typeInfo(Type).@"enum".fields) |fields| {
                if (@intFromEnum(self) == fields.value) {
                    comptime var name_buf: [fields.name.len]u8 = undefined;
                    _ = comptime std.ascii.upperString(&name_buf, fields.name);
                    const name = name_buf;

                    return &name;
                }
            }
            unreachable;
        }
    };

    tag: ?[]const u8,
    type: Type,
    text: []const u8,
};

pub const Server = struct {
    address: [4]u8,
    auth: *tls.config.CertKeyPair,

    pub fn start(self: *Server, allocator: std.mem.Allocator) !void {
        logger.info("Starting IMAP server", .{});
        defer logger.info("Stopped IMAP server", .{});

        const address = std.net.Address.initIp4(self.address, 993);
        var server = try address.listen(.{ .reuse_address = true });
        defer server.deinit();

        var pollfd = [1]std.posix.pollfd{
            .{
                .fd = server.stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }
        };
        while (!root.shut_down.load(.acquire)) {
            if (try std.posix.poll(&pollfd, 100) == 0) continue;

            const tcp = try server.accept();
            handleConnection(self, allocator, tcp);
        }
    }

    fn handleConnection(self: *const Server, allocator: std.mem.Allocator, tcp: std.net.Server.Connection) void {
        logger.info("New imap connection", .{});
        defer logger.info("Closing imap connection", .{});
        defer tcp.stream.close();

        var ca: std.heap.ArenaAllocator = .init(allocator);
        defer ca.deinit();

        var tls_stream = tls.server(tcp.stream, .{ .auth = self.auth }) catch |err| {
            logger.err("TLS error: {}", .{ err });
            return;
        };
        defer tls_stream.close() catch {};
        const reader = tls_stream.reader();
        const writer = tls_stream.writer();
        var conn = Connection{ .allocator = ca.allocator(), .logged_out = false, .user = null, .fd = tcp.stream.handle, .reader = reader, .writer = writer, .read_buf = undefined, .mailbox = null };

        conn.send(Response{ .tag = null, .type = .ok, .text = "[CAPABILITY IMAP4rev2 AUTH=PLAIN] IMAP4rev2 Service Ready" }) catch {
        // conn.send(Response{ .tag = null, .type = .ok, .text = "IMAP4rev2 Service Ready" }) catch {
            logger.err("Failed to send greeting", .{});
            return;
        };

        while (conn.state() != .logout and !root.shut_down.load(.acquire)) {
            const cmd = conn.read_command() catch |err| switch (err) {
                error.Timeout, error.StreamTooLong => continue,
                error.EndOfStream => return,
                else => break,
            };
            defer cmd.deinit(conn.allocator);
            logger.debug("{s} {s}", .{ cmd.tag, cmd.cmd });


            if (handlers.get(cmd.cmd)) |cmd_handler| {
                cmd_handler(&conn, &cmd) catch |err| {
                    switch (err) {
                        error.InvalidArguments => conn.send(cmd.bad("Invalid arguments")) catch break,
                        else => break,
                    }
                };
            } else {
                conn.send(.{ .tag = cmd.tag, .type = .bad, .text = "Unknown command" }) catch break;
            }
        }

        if (conn.state() != .logout) { // Closing connection due to an error
            conn.bye() catch {};
        }
    }
};

fn call_cmd_handler(conn: *Connection, cmd: *const Command, comptime handler: anytype) !void {
    const handler_info = @typeInfo(@TypeOf(handler));
    if (handler_info != .@"fn") {
        @compileError("call_cmd_handler: handler must be a function, not " ++ @typeName(@TypeOf(handler)));
    }

    const params = handler_info.@"fn".params;
    if (params.len < 2 or params[0].type != *Connection or params[1].type != *const Command) {
        @compileError("call_cmd_handler: handler must take a " ++ @typeName(*Connection) ++ " and a " ++ @typeName(*const Command) ++ " as its first two arguments");
    }

    if (cmd.args.len != params.len - 2 and params[params.len - 1].type.? != []const []const u8) {
        return error.InvalidArguments;
    }

    comptime var fields: [params.len]std.builtin.Type.StructField = undefined;
    inline for (params, 0..) |param, i| {
        if (param.type == null) {
            @compileError("I don't know what this means :/");
        }

        fields[i] = std.builtin.Type.StructField{
            .name = std.fmt.comptimePrint("{}", .{ i }),
            .type = param.type.?,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(param.type.?),
        };
    }

    const args_type_info = std.builtin.Type.Struct{
        .layout = .auto,
        .backing_integer = null,
        .fields = &fields,
        .decls = &.{},
        .is_tuple = true,
    };
    const args_type: type = @Type(std.builtin.Type{ .@"struct" = args_type_info });

    var args: args_type = undefined;
    @field(args, "0") = conn;
    @field(args, "1") = cmd;

    inline for (params[2..params.len], 2..) |param, i| {
        switch (param.type.?) {
            []const u8 => @field(args, std.fmt.comptimePrint("{}", .{ i })) = cmd.args[i - 2],
            []const []const u8 => {
                if (i != params.len - 1) {
                    @compileError("Invalid parameter type in command handler: " ++ @typeName(param.type.?) ++ " is only valid as the last parameter");
                } else {
                    @field(args, std.fmt.comptimePrint("{}", .{ i })) = cmd.args[i - 2..cmd.args.len];
                }
            },
            else => @compileError("Invalid parameter type in command handler: " ++ @typeName(param.type.?)),
        }
    }

    try @call(.auto, handler, args);
}


const std = @import("std");
const tls = @import("tls");
const root = @import("root");

const sasl = @import("sasl.zig");
const user_store = @import("user_store.zig");
const mailbox = @import("mailbox.zig");
