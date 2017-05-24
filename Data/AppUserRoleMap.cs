using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using IdSvr4POC.Models;

namespace IdSvr4POC.Data
{
    public class AppUserRoleMap
    {
        public AppUserRoleMap(EntityTypeBuilder<IdentityUserRole<long>> entityBuilder)
        {
             entityBuilder.ToTable("AspNetUserRoles");
             entityBuilder.HasKey(e=> new {e.RoleId, e.UserId});
        }
    }
}