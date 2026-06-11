using System.IdentityModel.Tokens.Jwt;
using System.Text;
using DainnUser.Application;
using DainnUser.Core.Configuration;
using DainnUser.Core.Interfaces.Repositories;
using DainnUser.Core.Interfaces.Services;
using DainnUser.Infrastructure.Configuration;
using DainnUser.Infrastructure.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace DainnUser.Infrastructure;

/// <summary>
/// Extension methods for configuring all DainnUser services.
/// </summary>
public static class DainnUserServiceExtensions
{
    /// <summary>
    /// Adds all DainnUser services to the service collection with default configuration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddDainnUser(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        return AddDainnUser(services, configuration, options => { });
    }

    /// <summary>
    /// Adds all DainnUser services to the service collection with custom configuration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration.</param>
    /// <param name="configureOptions">Action to configure DainnUser options.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddDainnUser(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<DainnUserOptions> configureOptions)
    {
        // Configure options
        var options = new DainnUserOptions();
        configureOptions(options);

        // Validate configuration
        ValidateConfiguration(configuration, services);

        services.TryAddSingleton(options);
        services.TryAddSingleton<IOptions<DainnUserOptions>>(Options.Create(options));

        // Add database context
        services.AddDainnUserDbContext(configuration);

        // Add repositories
        services.AddDainnUserRepositories();

        // Add application services
        services.AddDainnUserApplication();

        // Add infrastructure services
        services.AddDainnUserInfrastructure(configuration);

        // Add JWT bearer authentication + authorization
        services.AddDainnUserAuthentication(configuration);

        return services;
    }

    /// <summary>
    /// Registers JWT bearer authentication and authorization using DainnUser's JWT options.
    /// Called automatically by <see cref="AddDainnUser"/>. Can also be called standalone
    /// if only authentication registration is needed.
    /// </summary>
    public static IServiceCollection AddDainnUserAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Skip if authentication is already registered
        if (services.Any(d => d.ServiceType == typeof(Microsoft.AspNetCore.Authentication.IAuthenticationService)))
            return services;

        var jwt = configuration.GetSection("DainnUser:Jwt").Get<JwtOptions>() ?? new JwtOptions();

        if (string.IsNullOrWhiteSpace(jwt.Secret))
            return services; // Will be caught by ValidateConfiguration if mandatory

        var keyBytes = Encoding.UTF8.GetBytes(jwt.Secret);
        var signingKey = new SymmetricSecurityKey(keyBytes) { KeyId = "DainnUserSigningKey" };

        // Clear default inbound claim type map to preserve JWT claim names
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        services
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = jwt.ValidateIssuer,
                    ValidateAudience = jwt.ValidateAudience,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    ValidIssuer = jwt.Issuer,
                    ValidAudience = jwt.Audience,
                    IssuerSigningKey = signingKey,
                    ClockSkew = TimeSpan.FromSeconds(jwt.ClockSkewSeconds)
                };

                options.MapInboundClaims = false;
            });

        services.AddAuthorization();

        return services;
    }

    /// <summary>
    /// Validates required configuration settings.
    /// </summary>
    /// <param name="configuration">The configuration to validate.</param>
    /// <exception cref="InvalidOperationException">Thrown when required configuration is missing.</exception>
    private static void ValidateConfiguration(IConfiguration configuration, IServiceCollection services)
    {
        // Validate database configuration
        if (!services.Any(descriptor =>
                descriptor.ServiceType == typeof(IUnitOfWork) ||
                descriptor.ServiceType == typeof(IUserRepository)))
        {
            var connectionString = configuration["DainnUser:Database:ConnectionString"];
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                throw new InvalidOperationException(
                    "DainnUser database connection string is not configured. " +
                    "Please set 'DainnUser:Database:ConnectionString' in your configuration.");
            }

            var provider = configuration["DainnUser:Database:Provider"];
            if (string.IsNullOrWhiteSpace(provider))
            {
                throw new InvalidOperationException(
                    "DainnUser database provider is not configured. " +
                    "Please set 'DainnUser:Database:Provider' in your configuration. " +
                    "Supported providers: SqlServer, PostgreSQL, MySQL, SQLite");
            }

            var supportedProviders = new[] { "SqlServer", "PostgreSQL", "MySQL", "SQLite" };
            if (!supportedProviders.Contains(provider, StringComparer.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"Unsupported database provider: {provider}. " +
                    $"Supported providers: {string.Join(", ", supportedProviders)}");
            }
        }

        // Validate email configuration
        if (!services.Any(descriptor =>
                descriptor.ServiceType == typeof(IEmailService) ||
                descriptor.ServiceType == typeof(IEmailProvider)))
        {
            var fromEmail = configuration["DainnUser:Email:FromEmail"];
            if (string.IsNullOrWhiteSpace(fromEmail))
            {
                throw new InvalidOperationException(
                    "DainnUser email from address is not configured. " +
                    "Please set 'DainnUser:Email:FromEmail' in your configuration.");
            }

            var emailProvider = configuration["DainnUser:Email:Provider"] ?? "Smtp";
            switch (emailProvider.ToLowerInvariant())
            {
                case "smtp":
                    var smtpHost = configuration["DainnUser:Email:SmtpHost"];
                    if (string.IsNullOrWhiteSpace(smtpHost))
                    {
                        throw new InvalidOperationException(
                            "DainnUser email SMTP host is not configured. " +
                            "Please set 'DainnUser:Email:SmtpHost' in your configuration.");
                    }

                    var smtpPort = configuration["DainnUser:Email:SmtpPort"];
                    if (string.IsNullOrWhiteSpace(smtpPort) || !int.TryParse(smtpPort, out _))
                    {
                        throw new InvalidOperationException(
                            "DainnUser email SMTP port is not configured or invalid. " +
                            "Please set 'DainnUser:Email:SmtpPort' in your configuration.");
                    }

                    break;

                case "sendgrid":
                    var sendGridApiKey = configuration["DainnUser:Email:SendGridApiKey"];
                    if (string.IsNullOrWhiteSpace(sendGridApiKey))
                    {
                        throw new InvalidOperationException(
                            "DainnUser email SendGrid API key is not configured. " +
                            "Please set 'DainnUser:Email:SendGridApiKey' in your configuration.");
                    }

                    break;

                case "awsses":
                    var awsRegion = configuration["DainnUser:Email:AwsRegion"];
                    if (string.IsNullOrWhiteSpace(awsRegion))
                    {
                        throw new InvalidOperationException(
                            "DainnUser email AWS region is not configured. " +
                            "Please set 'DainnUser:Email:AwsRegion' in your configuration.");
                    }

                    var awsAccessKeyId = configuration["DainnUser:Email:AwsAccessKeyId"];
                    if (string.IsNullOrWhiteSpace(awsAccessKeyId))
                    {
                        throw new InvalidOperationException(
                            "DainnUser email AWS access key ID is not configured. " +
                            "Please set 'DainnUser:Email:AwsAccessKeyId' in your configuration.");
                    }

                    var awsSecretAccessKey = configuration["DainnUser:Email:AwsSecretAccessKey"];
                    if (string.IsNullOrWhiteSpace(awsSecretAccessKey))
                    {
                        throw new InvalidOperationException(
                            "DainnUser email AWS secret access key is not configured. " +
                            "Please set 'DainnUser:Email:AwsSecretAccessKey' in your configuration.");
                    }

                    break;

                default:
                    throw new InvalidOperationException(
                        $"Unsupported email provider: '{emailProvider}'. Supported providers: Smtp, SendGrid, AwsSes.");
            }
        }

        // Validate JWT configuration
        if (!services.Any(descriptor => descriptor.ServiceType == typeof(IJwtTokenService)))
        {
            var jwtSecret = configuration["DainnUser:Jwt:Secret"];
            if (string.IsNullOrWhiteSpace(jwtSecret))
            {
                throw new InvalidOperationException(
                    "DainnUser JWT secret is not configured. " +
                    "Please set 'DainnUser:Jwt:Secret' in your configuration. " +
                    "The secret must be at least 32 characters (256 bits).");
            }

            if (System.Text.Encoding.UTF8.GetByteCount(jwtSecret) < 32)
            {
                throw new InvalidOperationException(
                    "DainnUser JWT secret is too short. It must be at least 32 bytes (256 bits) for HMAC-SHA256.");
            }
        }
    }
}
