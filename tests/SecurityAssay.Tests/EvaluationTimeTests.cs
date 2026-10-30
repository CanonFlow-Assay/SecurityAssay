using CanonFlow.Security.Adapters;
using Xunit;

namespace SecurityAssay.Tests;

public sealed class EvaluationTimeTests
{
    [Theory]
    [InlineData("2026-10-29T06:00:00Z")]
    [InlineData("2026-10-29T06:00:00.0000000Z")]
    [InlineData("2026-10-29T06:00:00+00:00")]
    [InlineData("2026-10-29T06:00:00.0000000+00:00")]
    public void QualificationCanUseTheActualCurrentDatabaseEra(string text)
        => Assert.Equal(new DateTimeOffset(2026, 10, 29, 6, 0, 0, TimeSpan.Zero), EvaluationTime.ParseUtc(text));

    [Theory]
    [InlineData("2026-10-29T06:00:00")]
    [InlineData("2026-10-29T06:00:00+01:00")]
    [InlineData("2026-10-29")]
    [InlineData("current")]
    [InlineData("2026-02-30T00:00:00Z")]
    public void QualificationRejectsAmbiguousOrNonUtcEvaluationTime(string text)
        => Assert.Throws<ArgumentException>(() => EvaluationTime.ParseUtc(text));
}
