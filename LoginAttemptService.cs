using Microsoft.Extensions.Caching.Memory;

public class LoginAttemptService
{
    private readonly IMemoryCache _cache;

    private const int MAX_ATTEMPTS = 5;
    private static readonly TimeSpan BLOCK_TIME = TimeSpan.FromMinutes(10);

    public LoginAttemptService(IMemoryCache cache)
    {
        _cache = cache;
    }

    private string GetKey(string ip, string username)
        => $"{ip}:{username}".ToLowerInvariant();

    public bool IsBlocked(string ip, string username)
    {
        return _cache.TryGetValue(GetKey(ip, username), out int attempts)
               && attempts >= MAX_ATTEMPTS;
    }

    public void RegisterFailedAttempt(string ip, string username)
    {
        var key = GetKey(ip, username);

        var attempts = _cache.GetOrCreate(key, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = BLOCK_TIME;
            return 0;
        });

        attempts++;

        _cache.Set(key, attempts, BLOCK_TIME);
    }

    public void Reset(string ip, string username)
    {
        _cache.Remove(GetKey(ip, username));
    }
}
