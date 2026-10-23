using System.Runtime.InteropServices;

namespace CanonFlow.Security.Adapters;

internal static class RegularFiles
{
    // M0 supports Linux. statx distinguishes regular files from FIFOs/devices,
    // which File.Exists/GetAttributes alone do not establish on Unix.
    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct StatxBuffer { [FieldOffset(28)] public ushort Mode; }

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int Statx(int directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out StatxBuffer result);

    internal static void Require(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidDataException("Regular-file qualification is Linux-only in M0.");
        if (Statx(-100, path, 0x100 | 0x800, 1, out var result) != 0) throw new IOException("Cannot establish regular input file type.");
        if ((result.Mode & 0xf000) != 0x8000) throw new InvalidDataException("Only regular input files are supported; devices/FIFOs/sockets are forbidden.");
    }
}
