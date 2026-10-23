using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace CanonFlow.Security.Adapters;

public static class JsonIO
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) }
    };
    public static string ShaFile(string path) { using var stream = File.OpenRead(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    public static string ShaText(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    public static string Canonical(JsonNode? value) => value switch
    {
        JsonObject obj => "{" + string.Join(',', obj.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => JsonSerializer.Serialize(p.Key) + ":" + Canonical(p.Value))) + "}",
        JsonArray array => "[" + string.Join(',', array.Select(Canonical)) + "]",
        _ => value?.ToJsonString() ?? "null"
    };
    public static string Digest(JsonNode value) => ShaText(Canonical(value));
    public static JsonNode Node(object value) => JsonSerializer.SerializeToNode(value, Options) ?? throw new InvalidDataException("Missing value.");
    public static void Write(string path, object value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, Canonical(value as JsonNode ?? Node(value)) + "\n");
    }
    public static JsonNode Parse(string text)
    {
        if (Encoding.UTF8.GetByteCount(text) > 32 * 1024 * 1024) throw new InvalidDataException("JSON exceeds the evidence limit.");
        using var document = JsonDocument.Parse(text); Unique(document.RootElement);
        return JsonNode.Parse(text) ?? throw new InvalidDataException("Missing JSON document.");
    }
    public static JsonNode Read(string path) => new FileInfo(path).Length > 32 * 1024 * 1024
        ? throw new InvalidDataException("JSON exceeds the evidence limit.") : Parse(File.ReadAllText(path));
    public static T Load<T>(string path) => Read(path).Deserialize<T>(Options) ?? throw new InvalidDataException("Missing typed JSON.");
    private static void Unique(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in value.EnumerateObject()) { if (!names.Add(p.Name)) throw new InvalidDataException("Duplicate JSON property."); Unique(p.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Unique(item);
    }
    public static string Text(JsonNode? value, string name) => value?[name]?.GetValue<string>() ?? throw new InvalidDataException("Missing string: " + name);
    public static JsonArray Array(JsonNode value, string name) => value[name] as JsonArray ?? throw new InvalidDataException("Missing array: " + name);
}
