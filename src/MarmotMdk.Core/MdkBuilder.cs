using MarmotMdk.Storage.Abstractions;
using Microsoft.Extensions.Logging;

namespace MarmotMdk.Core;

/// <summary>
/// Fluent builder for constructing an <see cref="Mdk{TStorage}"/> instance.
/// </summary>
/// <typeparam name="TStorage">The storage provider implementation type.</typeparam>
public sealed class MdkBuilder<TStorage> where TStorage : IMdkStorageProvider
{
    private TStorage? _storage;
    private MdkConfig _config = MdkConfig.Default;
    private IMdkCallback? _callback;
    private ILogger? _logger;

    /// <summary>
    /// Sets the storage provider implementation.
    /// </summary>
    public MdkBuilder<TStorage> WithStorage(TStorage storage)
    {
        _storage = storage;
        return this;
    }

    /// <summary>
    /// Sets the MDK configuration. If not called, <see cref="MdkConfig.Default"/> is used.
    /// </summary>
    public MdkBuilder<TStorage> WithConfig(MdkConfig config)
    {
        _config = config;
        return this;
    }

    /// <summary>
    /// Sets the callback for group state change notifications.
    /// </summary>
    public MdkBuilder<TStorage> WithCallback(IMdkCallback callback)
    {
        _callback = callback;
        return this;
    }

    /// <summary>
    /// Sets the logger. If not called, a null logger is used.
    /// </summary>
    public MdkBuilder<TStorage> WithLogger(ILogger logger)
    {
        _logger = logger;
        return this;
    }

    /// <summary>
    /// Builds and returns a new <see cref="Mdk{TStorage}"/> instance.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when the storage provider has not been set.</exception>
    public Mdk<TStorage> Build()
    {
        if (_storage == null)
            throw new InvalidOperationException("Storage provider is required.");

        return new Mdk<TStorage>(_storage, _config, _callback, _logger);
    }
}
