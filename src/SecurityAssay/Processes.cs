using System.Diagnostics;
using System.Text;

namespace CanonFlow.Security.Adapters;

public sealed record ProcessEvidence(int ExitCode, string Output, string Error, bool TimedOut);

public static class Processes
{
    public static async Task<ProcessEvidence> Run(string[] arguments, int seconds = 120, string? directory = null,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        using var process = new Process { StartInfo = new ProcessStartInfo(arguments[0]) { UseShellExecute = false,
            WorkingDirectory = directory ?? Directory.GetCurrentDirectory(), RedirectStandardOutput = true, RedirectStandardError = true } };
        foreach (var argument in arguments.Skip(1)) process.StartInfo.ArgumentList.Add(argument);
        if (environment is not null) foreach (var (key, value) in environment) process.StartInfo.Environment[key] = value;
        process.Start(); var stdout = Read(process.StandardOutput); var stderr = Read(process.StandardError);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(seconds)); var timedOut = false;
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException) { timedOut = true; process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); }
        return new(process.ExitCode, await stdout, await stderr, timedOut);
    }
    private static async Task<string> Read(StreamReader reader)
    {
        var text = new StringBuilder(); var buffer = new char[8192]; int count; var overflow = false;
        while ((count = await reader.ReadAsync(buffer)) > 0)
        {
            // Continue draining to avoid deadlock while retaining only the bounded prefix.
            var remaining = 32 * 1024 * 1024 - text.Length;
            if (count > remaining) overflow = true;
            if (remaining > 0) text.Append(buffer, 0, Math.Min(count, remaining));
        }
        if (overflow) throw new InvalidDataException("Tool output exceeds the evidence boundary.");
        return text.ToString();
    }
    public static async Task<ProcessEvidence> Docker(string imageId, string[] command, string[] mounts, int seconds = 120)
    {
        var name = "security-assay-" + Guid.NewGuid().ToString("N");
        try
        {
            var create = await Run(["docker", "create", "--pull=never", "--name", name, "--network", "none", "--read-only", "--user", "65532:65532",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "1536m", "--cpus", "2",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=134217728", "--env", "HOME=/tmp", "--env", "XDG_CACHE_HOME=/tmp",
                .. mounts.SelectMany(m => new[] { "--mount", m }), imageId, .. command], 30);
            if (create.ExitCode != 0 || create.TimedOut) return create;
            var inspect = await Run(["docker", "inspect", name], 15); var settings = JsonIO.Parse(inspect.Output)[0]!;
            if (inspect.ExitCode != 0 || JsonIO.Text(settings["HostConfig"], "NetworkMode") != "none" ||
                settings["HostConfig"]?["ReadonlyRootfs"]?.GetValue<bool>() != true || settings["HostConfig"]?["Privileged"]?.GetValue<bool>() != false ||
                JsonIO.Text(settings["Config"], "User") != "65532:65532" ||
                (settings["HostConfig"]?["CapDrop"] as System.Text.Json.Nodes.JsonArray)?.Any(c => c?.GetValue<string>() == "ALL") != true ||
                (settings["HostConfig"]?["SecurityOpt"] as System.Text.Json.Nodes.JsonArray)?.Any(c => c?.GetValue<string>().StartsWith("no-new-privileges", StringComparison.Ordinal) == true) != true ||
                settings["HostConfig"]?["Memory"]?.GetValue<long>() is not (> 0 and <= 2147483648) ||
                settings["HostConfig"]?["PidsLimit"]?.GetValue<long>() is not (> 0 and <= 128) ||
                (settings["Mounts"] as System.Text.Json.Nodes.JsonArray)?.Any(m => m?["Type"]?.GetValue<string>() == "bind" && m["RW"]?.GetValue<bool>() != false) == true)
                throw new InvalidDataException("Actual container settings contradict declared isolation.");
            var execution = await Run(["docker", "start", "--attach", name], seconds);
            if (execution.TimedOut) return execution;
            var state = await Run(["docker", "inspect", "--format", "{{.State.ExitCode}}", name], 15);
            if (state.ExitCode != 0 || !int.TryParse(state.Output.Trim(), out var code)) throw new InvalidDataException("Missing container exit evidence.");
            return execution with { ExitCode = code };
        }
        finally { _ = await Run(["docker", "rm", "--force", name], 15); }
    }
    public static string Mount(string source, string target)
    {
        source = Path.GetFullPath(source);
        if (source.Contains(',') || source.Any(char.IsControl)) throw new InvalidDataException("Ambiguous mount source.");
        return "type=bind,source=" + source + ",target=" + target + ",readonly";
    }
}
