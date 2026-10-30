using System.Globalization;

namespace CanonFlow.Security.Adapters;

public static class EvaluationTime
{
    private static readonly string[] Formats = [
        "yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'",
        "yyyy-MM-dd'T'HH:mm:sszzz", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFzzz"
    ];

    public static DateTimeOffset ParseUtc(string value)
    {
        if (!DateTimeOffset.TryParseExact(value, Formats, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var instant) || instant.Offset != TimeSpan.Zero)
            throw new ArgumentException("Use an ISO UTC evaluation timestamp ending in Z or +00:00.");
        return instant;
    }
}
