const Config = struct {
    db_path: []const u8 = "./talaria.db",
    user_db_path: []const u8 = "./user_dbs",
};


pub var values: Config = undefined;


const logger = std.log.scoped(.config);
var arena: std.heap.ArenaAllocator = undefined;


pub fn init(gpa: std.mem.Allocator) !void {
    arena = .init(gpa);
    const allocator = arena.allocator();

    var db_path = args.StringArgument.init(&.{ "db_path" }, "", "");
    var user_db_path = args.StringArgument.init(&.{ "user_db_path" }, "", "");
    var config = args.StringArgument.init(&.{ "config_path" }, "", "./config.zon");


    var arguments = [_]*args.Argument{ &db_path.arg, &user_db_path.arg, &config.arg };
    var posArguments = [_]*args.PositionalArgument{ };
    try args.parseArgv(&arguments, &posArguments);


    var parse_status = std.zon.parse.Diagnostics{};
    defer parse_status.deinit(allocator);
    values = blk: {
        const config_str = std.fs.cwd().readFileAllocOptions(allocator, config.value, 8192, null, .fromByteUnits(@alignOf(u8)), 0) catch break :blk .{};
        defer allocator.free(config_str);
        break :blk std.zon.parse.fromSlice(Config, allocator, config_str, &parse_status, .{ .free_on_error = true }) catch |err| {
            if (parse_status.type_check) |tc| {
                logger.err("{s}", .{tc.message});
            }
            return err;
        };
    };

    set_value("db_path", db_path);
    set_value("user_db_path", user_db_path);
}

pub fn deinit() void {
    arena.deinit();
}

fn set_value(comptime name: []const u8, arg: anytype) void {
    if (arg.found) {
        @field(values, name) = arg.value;
    }
}


const std = @import("std");
const args = @import("args");
