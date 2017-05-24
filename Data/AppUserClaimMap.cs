using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using IdSvr4POC.Models;

namespace IdSvr4POC.Data
{
    public class AppUserClaimMap{

        public AppUserClaimMap(EntityTypeBuilder<IdentityUserClaim<long>> entityBuilder)
        {
            entityBuilder.ToTable("AspNetUserClaims");
            entityBuilder.HasKey(e=>e.Id);
            entityBuilder.Property(e=>e.UserId).IsRequired();
        }
    }
}