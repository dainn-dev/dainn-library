using DainnUser.Core.Authorization;
using DainnUser.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DainnUser.Api.Extensions;

/// <summary>
/// Extension methods for configuring JWT bearer authentication.
/// </summary>
public static class JwtAuthenticationExtensions
{
    /// <summary>
    /// Registers JWT bearer authentication using DainnUser's JWT options.
    /// Reads <c>DainnUser:Jwt</c> from configuration and binds <see cref="DainnUser.Infrastructure.Configuration.JwtOptions"/>.
    /// <para>
    /// Note: <c>AddDainnUser()</c> now calls this automatically. This method is kept for
    /// backward compatibility — calling it again is safe (idempotent).
    /// </para>
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The application configuration.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddDainnUserJwtAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Delegate to the Infrastructure method (handles idempotency internally)
        services.AddDainnUserAuthentication(configuration);

        // Add DainnUser-specific authorization policies
        services.AddAuthorization(options =>
        {
            options.AddPolicy(DainnUserPolicies.CanReadUsers, policy =>
                policy.RequireClaim(DainnUserClaimTypes.Permission, DainnUserPermissions.UsersRead));
            options.AddPolicy(DainnUserPolicies.CanWriteUsers, policy =>
                policy.RequireClaim(DainnUserClaimTypes.Permission, DainnUserPermissions.UsersWrite));
            options.AddPolicy(DainnUserPolicies.CanDeleteUser, policy =>
                policy.RequireClaim(DainnUserClaimTypes.Permission, DainnUserPermissions.UsersDelete));
            options.AddPolicy(DainnUserPolicies.CanManageRoles, policy =>
                policy.RequireClaim(DainnUserClaimTypes.Permission, DainnUserPermissions.RolesWrite));
            options.AddPolicy(DainnUserPolicies.CanDeleteRole, policy =>
                policy.RequireClaim(DainnUserClaimTypes.Permission, DainnUserPermissions.RolesDelete));
            options.AddPolicy(DainnUserPolicies.CanManageSettings, policy =>
                policy.RequireClaim(DainnUserClaimTypes.Permission, DainnUserPermissions.SettingsWrite));
        });

        return services;
    }
}
