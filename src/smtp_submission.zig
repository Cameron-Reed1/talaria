const command_handler = *const fn(conn: *Connection, cmd: *const Command) anyerror!void;
const handlers: std.StaticStringMap(command_handler) = .initComptime(.{
    .{ "EHLO", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_ex_hello); } }.handle },
    .{ "HELO", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_hello); } }.handle },
    .{ "MAIL", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_mail); } }.handle },
    .{ "RCPT", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_receipt); } }.handle },
    .{ "DATA", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_data); } }.handle },
    .{ "RSET", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_reset); } }.handle },
    .{ "VRFY", handle_unimplemented },
    .{ "EXPN", handle_unimplemented },
    .{ "HELP", handle_unimplemented },
    .{ "NOOP", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_noop); } }.handle },
    .{ "QUIT", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_quit); } }.handle },
    .{ "STARTTLS", handle_unimplemented },
    .{ "AUTH", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_auth); } }.handle },
    .{ "ATRN", handle_unimplemented },
    .{ "BDAT", struct { fn handle(conn: *Connection, cmd: *const Command) !void { return call_cmd_handler(conn, cmd, handle_binary_data); } }.handle },
    .{ "ETRN", handle_unimplemented },
});


const logger = std.log.scoped(.smtp);


const CommandError = error {
    InvalidArguments,
};


fn handle_ex_hello(conn: *Connection, server_name: []const u8) !void {
    conn.state.remote_domain = try conn.allocator.dupe(u8, server_name);
    try conn.send(.{ .code = 250, .continued = true, .text = "Hello" });
    try conn.send(.{ .code = 250, .continued = false, .text = "AUTH PLAIN" });
}

fn handle_hello(conn: *Connection, server_name: []const u8) !void {
    conn.state.remote_domain = try conn.allocator.dupe(u8, server_name);
    try conn.send(.{ .code = 250, .continued = false, .text = "OK" });
}

fn handle_mail(conn: *Connection, from: []const u8) !void {
    if (from.len < 5) {
        return CommandError.InvalidArguments;
    }

    if (!std.ascii.eqlIgnoreCase(from[0..5], "FROM:")) {
        return CommandError.InvalidArguments;
    }

    const from_addr = from[5..from.len];
    if (!accept_from_addr(conn, from_addr)) {
        try conn.send(.{ .code = 550, .continued = false, .text = "Rejected" });
        return;
    }
    conn.state.from = try conn.allocator.dupe(u8, from_addr);

    try conn.send(.{ .code = 250, .continued = false, .text = "OK" });
}

fn handle_receipt(conn: *Connection, addr: []const u8) !void {
    if (addr.len < 5) {
        return CommandError.InvalidArguments;
    }

    if (!std.ascii.eqlIgnoreCase(addr[0..4], "TO:<") or addr[addr.len - 1] != '>') {
        return CommandError.InvalidArguments;
    }

    const to_addr = addr[4..addr.len - 1];
    if (conn.state.to.items.len != 0) {
        try conn.state.to.append(conn.allocator, ':');
    }
    try conn.state.to.appendSlice(conn.allocator, to_addr);

    try conn.send(.{ .code = 250, .continued = false, .text = "OK" });
}

fn handle_data(conn: *Connection) !void {
    try conn.send(.{ .code = 354, .continued = false, .text = "Start mail input; end with <CRLF>.<CRLF>" });

    var last_line_empty = false;
    while (true) {
        var line = try conn.read_line();

        if (line.len == 0) {
            last_line_empty = true;
            continue;
        }

        if (std.mem.eql(u8, line, ".") and last_line_empty) {
            line = try conn.read_line();
            if (line.len == 0) break; // End of data

            try conn.state.message.appendSlice(conn.allocator, "\r\n.\r\n");
        }

        try conn.state.message.appendSlice(conn.allocator, line);
        try conn.state.message.appendSlice(conn.allocator, "\r\n");
    }

    logger.info("New message that needs to be sent:\n\tFrom: {s}\n\tRecipients: {s}\n\tMessage: {s}", .{ conn.state.from.?, conn.state.to.items, conn.state.message.items });
    conn.state.reset(conn.allocator);

    try conn.send(.{ .code = 250, .continued = false, .text = "OK" });
}

fn handle_binary_data(conn: *Connection, len_s: []const u8, terminating: []const u8) !void {
    _ = terminating;
    const len = try std.fmt.parseInt(usize, len_s, 10);
    const buf = try conn.reader.readAlloc(conn.allocator, len);
    defer conn.allocator.free(buf);
    try conn.state.message.appendSlice(conn.allocator, buf);

    logger.info("New message that needs to be sent:\n\tFrom: {s}\n\tRecipients: {s}\n\tMessage: {s}", .{ conn.state.from.?, conn.state.to.items, conn.state.message.items });
    conn.state.reset(conn.allocator);

    try conn.send(.{ .code = 250, .continued = false, .text = "OK" });
}

fn handle_reset(conn: *Connection) !void {
    conn.state.reset(conn.allocator);
    try conn.send(.{ .code = 250, .continued = false, .text = "State reset" });
}

fn handle_noop(conn: *Connection) !void {
    try conn.send(.{ .code = 250, .continued = false, .text = "OK" });
}

fn handle_quit(conn: *Connection) !void {
    conn.state.quit = true;
    try conn.send(.{ .code = 221, .continued = false, .text = "mail-test.cam123.dev Service closing transmission channel" });
}

fn handle_auth(conn: *Connection, mechanism: []const u8, initial_response: ?[]const u8) !void {
    if (!std.mem.eql(u8, mechanism, "PLAIN")) {
        try conn.send(.{ .code = 504, .continued = false, .text = "Unsupported auth mechanism" });
        return;
    }

    const input = if (initial_response) |i| i else blk: {
        try conn.send(.{ .code = 334, .continued = false, .text = "" });
        break :blk try conn.read_line();
    };
    const details = try sasl.plain_read_details(conn.allocator, input);
    defer details.deinit(conn.allocator);
    if (sasl.plain(conn.allocator, details)) {
        conn.state.user = try conn.allocator.dupe(u8, details.authzid);
        try conn.send(.{ .code = 235, .continued = false, .text = "OK" });
    } else {
        logger.debug("Failed to authenticate with credentials: authzid={s} (len={}), authcid={s} (len={}), password={s} (len={})", .{ details.authzid, details.authzid.len, details.authcid, details.authcid.len, details.passwd, details.passwd.len });
        try conn.send(.{ .code = 535, .continued = false, .text = "Invalid credentials" });
    }
}

fn handle_unimplemented(conn: *Connection, _: *const Command) !void {
    try conn.send(.{ .code = 502, .continued = false, .text = "Command not implemented" });
}



fn accept_from_addr(conn: *Connection, addr: []const u8) bool {
    if (conn.state.user == null) { // Don't allow any connections that haven't been authenticated yet
        return false;
    }

    var i: usize = 0;
    const local = blk: while (true) {
        if (i >= addr.len) return false; // No '@' in address
        if (addr[i] == '@') break :blk addr[0..i];
        i += 1;
    };

    i += 1;
    if (i >= addr.len) return false; // No domain

    const domain = addr[i..addr.len];
    return std.mem.eql(u8, local, conn.state.user.?) and std.mem.eql(u8, domain, "mail-test.cam123.dev");
}


const SMTPState = struct {
    remote_domain: ?[]const u8,
    user: ?[]const u8,
    from: ?[]const u8,
    to: std.ArrayListUnmanaged(u8),
    message: std.ArrayListUnmanaged(u8),
    quit: bool,

    const default = SMTPState{ .remote_domain = null, .user = null, .from = null, .to = .empty, .message = .empty, .quit = false };

    fn deinit(self: *SMTPState, allocator: std.mem.Allocator) void {
        if (self.user) |u| {
            allocator.free(u);
        }

        if (self.remote_domain) |d| {
            allocator.free(d);
        }

        self.reset(allocator);
    }

    fn reset(self: *SMTPState, allocator: std.mem.Allocator) void {
        if (self.from) |f| {
            allocator.free(f);
        }
        self.from = null;
        self.to.clearAndFree(allocator);
        self.message.clearAndFree(allocator);
    }
};


const Connection = struct {
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    state: SMTPState,
    read_buf: [8192]u8,

    const ReadError = error {
        CommandTooLong,
    };

    fn read_line(self: *Connection) ![]const u8 {
        var idx: u16 = 0;
        var c1: u8 = 0;
        var c2: u8 = try self.reader.takeByte();

        while (idx < self.read_buf.len) {
            c1 = c2;
            c2 = try self.reader.takeByte();

            if (c1 == '\r' and c2 == '\n') {
                return self.read_buf[0..idx];
            }

            self.read_buf[idx] = c1;
            idx += 1;
        }

        return ReadError.CommandTooLong;
    }

    fn read_command(self: *Connection) !Command {
        const input = self.read_line() catch |err| {
            if (err == error.CommandTooLong) {
                try self.send(.{ .code = 502, .continued = false, .text = "Command too long" });
            }
            return err;
        };

        return try Command.parse(self.allocator, input);
    }

    fn send(self: *Connection, msg: Response) !void {
        if (msg.continued) {
            const fmt = "{}-{s}";
            logger.debug(fmt, .{ msg.code, msg.text });
            try self.writer.print(fmt ++ "\r\n", .{ msg.code, msg.text });
        } else {
            const fmt = "{} {s}";
            logger.debug(fmt, .{ msg.code, msg.text });
            try self.writer.print(fmt ++ "\r\n", .{ msg.code, msg.text });
        }
        try self.writer.flush();
    }

    fn deinit(self: *Connection) void {
        self.state.deinit(self.allocator);
    }
};


const Command = struct {
    cmd: []const u8,
    args: [][]const u8,

    fn parse(allocator: std.mem.Allocator, input_str: []const u8) !Command {
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

            try args.append(allocator, input_str[start..end]);
        }

        return Command{
            .cmd = cmd,
            .args = try args.toOwnedSlice(allocator),
        };
    }

    fn deinit(self: *const Command, allocator: std.mem.Allocator) void {
        allocator.free(self.cmd);
        allocator.free(self.args);
    }
};

const Response = struct {
    code: u16,
    continued: bool,
    text: []const u8,
};

pub const Server = struct {
    address: [4]u8,
    auth: *tls.config.CertKeyPair,

    pub fn start(self: *Server, allocator: std.mem.Allocator) !void {
        logger.info("Starting SMTP submission server", .{});
        defer logger.info("Stopped SMTP submission server", .{});

        const address = std.net.Address.initIp4(self.address, 465);
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
        logger.info("New mail submission connection", .{});
        defer logger.info("Closing mail submission connection", .{});
        defer tcp.stream.close();

        var ca: std.heap.ArenaAllocator = .init(allocator);
        defer ca.deinit();

        var tls_stream = tls.serverFromStream(tcp.stream, .{ .auth = self.auth }) catch |err| {
            logger.err("TLS error: {}", .{err});
            return;
        };
        defer tls_stream.close() catch {};

        var read_buf: [2048]u8 = undefined;
        var write_buf: [2048]u8 = undefined;
        var reader = tls_stream.reader(&read_buf);
        var writer = tls_stream.writer(&write_buf);

        var conn = Connection{ .allocator = ca.allocator(), .reader = &reader.interface, .writer = &writer.interface, .read_buf = undefined, .state = .default };
        defer conn.deinit();

        conn.send(Response{ .code = 220, .continued = false, .text = "mail-test.cam123.dev Service ready" }) catch {
            logger.err("Failed to send greeting", .{});
            return;
        };

        while (!conn.state.quit) {
            const cmd = conn.read_command() catch |err| switch (err) {
                error.CommandTooLong => continue,
                error.EndOfStream => return,
                else => break,
            };
            defer cmd.deinit(conn.allocator);
            logger.debug("{s} {f}", .{ cmd.cmd, utils.fmt.strSlice(cmd.args) });


            if (handlers.get(cmd.cmd)) |cmd_handler| {
                cmd_handler(&conn, &cmd) catch |err| {
                    switch (err) {
                        error.InvalidArguments => conn.send(.{ .code = 501, .continued = false, .text = "Bad arguments" }) catch break,
                        else => break,
                    }
                };
            } else {
                conn.send(.{ .code = 502, .continued = false, .text = "Unknown command" }) catch break;
            }
        }

        if (!conn.state.quit) {
            conn.send(.{ .code = 421, .continued = false, .text = "Closing connection" }) catch {};
        }
    }
};

fn call_cmd_handler(conn: *Connection, cmd: *const Command, comptime handler: anytype) !void {
    const handler_info = @typeInfo(@TypeOf(handler));
    if (handler_info != .@"fn") {
        @compileError("call_cmd_handler: handler must be a function, not " ++ @typeName(@TypeOf(handler)));
    }

    const params = handler_info.@"fn".params;
    if (params.len < 1 or params[0].type != *Connection) {
        @compileError("call_cmd_handler: handler must take a " ++ @typeName(*Connection) ++ " as its first argument");
    }

    comptime var param_count: u16 = 0;
    comptime var optional_param_count: u16 = 0;
    comptime var accepts_extra_params = false;

    inline for (params[1..params.len], 1..) |param, i| {
        switch (param.type.?) {
            []const u8 => {
                if (optional_param_count != 0) @compileError("Optional parameters must come after all required parameters in command handlers");
                param_count += 1;
            },
            ?[]const u8 => optional_param_count += 1,
            []const []const u8 => {
                if (i != params.len - 1) @compileError("Invalid parameter type in command handler: " ++ @typeName(param.type.?) ++ " is only valid as the last parameter");
                accepts_extra_params = true;
            },
            else => @compileError("Invalid parameter type in command handler: " ++ @typeName(param.type.?)),
        }
    }

    if (cmd.args.len < param_count or (cmd.args.len > param_count + optional_param_count and !accepts_extra_params)) {
        return error.InvalidArguments;
    }

    comptime var fields: [params.len]std.builtin.Type.StructField = undefined;
    inline for (params, 0..) |param, i| {
        if (param.type == null) {
            @compileError("I don't know what this means, but it isn't allowed here :/"); // Hopefully no one ever gets this error
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

    inline for (params[1..params.len], 1..) |param, i| {
        switch (param.type.?) {
            []const u8 => @field(args, std.fmt.comptimePrint("{}", .{ i })) = cmd.args[i - 1],
            ?[]const u8 => @field(args, std.fmt.comptimePrint("{}", .{ i })) = if (cmd.args.len <= i - 1) null else cmd.args[i - 1],
            []const []const u8 => @field(args, std.fmt.comptimePrint("{}", .{ i })) = cmd.args[i - 1..cmd.args.len],
            else => unreachable,
        }
    }

    try @call(.always_inline, handler, args);
}


pub const Client = struct {
    // pub fn send_message(allocator: std.mem.Allocator, from: []const u8, to: [][]const u8, message: []const u8) !void {
    //     for (to) |recipient| {
    //         var iter = std.mem.splitScalar(u8, recipient, '@');
    //         if (iter.next() == null) return error.A;
    //         const domain = iter.next();
    //         if (domain == null) return error.A;
    //         if (iter.next() != null) return error.A;
    //
    //         const stream = try std.net.tcpConnectToHost(allocator, domain, 25);
    //
    //         read_response(); // Should be 221
    //         stream.writeAll("EHLO mail-test.cam123.dev");
    //         read_response(); // Read until the response isn't continued, and check if STARTTLS is available
    //         if (starttls) {
    //             stream.writeAll("STARTTLS");
    //             read_response(); // Check that it is valid
    //             // Then start tls
    //         }
    //
    //         stream.writeAll("MAIL FROM:{from}");
    //         read_response(); // Check that it is valid
    //         stream.writeAll("RCPT TO:{recipient}");
    //         read_response(); // Check that it is valid
    //         stream.writeAll("DATA");
    //         read_response(); // Check that it is valid
    //         stream.writeAll("{mesage}\r\n.\r\n");
    //         read_response(); // Check that it is valid
    //         stream.writeAll("QUIT");
    //         read_response(); // Check that it is valid
    //         stream.close();
    //     }
    // }
};




test "Command parsing" {
    {
        const cmd = try Command.parse(std.testing.allocator, "NOOP");
        defer cmd.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("NOOP", cmd.cmd);
        try std.testing.expect(cmd.args.len == 0);
    }

    {
        const cmd = try Command.parse(std.testing.allocator, "auTH PLAIN garbage");
        defer cmd.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("AUTH", cmd.cmd);
        try std.testing.expect(cmd.args.len == 2);
        try std.testing.expectEqualStrings("PLAIN", cmd.args[0]);
        try std.testing.expectEqualStrings("garbage", cmd.args[1]);
    }

    {
        const cmd = try Command.parse(std.testing.allocator, ""); // TODO: make this return an error
        defer cmd.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings("", cmd.cmd);
        try std.testing.expect(cmd.args.len == 0);
    }
}




const std = @import("std");
const tls = @import("tls");
const root = @import("root");

const sasl = @import("sasl.zig");
const utils = @import("utils.zig");
