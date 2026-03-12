pub fn checkNullFormat(t: ?[]const u8) []const u8 {
    if (t == null) {
        return "null";
    }
    return t.?;
}
