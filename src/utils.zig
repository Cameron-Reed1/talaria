pub const fmt = struct {
    pub fn strSlice(value: []const []const u8) FStrSlice {
        return .{ .value = value };
    }


    const FStrSlice = struct {
        value: []const []const u8,

        pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.writeAll("[ ");
            var first = true;
            for (self.value) |s| {
                if (first) {
                    try writer.print("\"{s}\"", .{s});
                } else {
                    try writer.print(", \"{s}\"", .{s});
                }
                first = false;
            }
            try writer.writeAll(" ]");
        }
    };
};


const std = @import("std");
