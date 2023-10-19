using Microsoft.EntityFrameworkCore;
using PaintyTest.Models;

namespace PaintyTest.ApplicationContexts;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext()
    {
    }

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Account> Accounts { get; set; }
    public virtual DbSet<UsersImage> UsersImages { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Account>()
            .HasMany(e => e.UsersImages)
            .WithOne(e => e.Account)
            .HasForeignKey(e => e.AccountId)
            .HasPrincipalKey(e => e.AccountId);

        modelBuilder.Entity<Account>()
            .HasMany(e => e.Friends)
            .WithMany(e => e.FriendOf)
            .UsingEntity<FriendsOfFriends>
            (
                 right => right
                        .HasOne(joinEntity => joinEntity.UsersFriend)
                        .WithMany(),
                    left => left
                        .HasOne(joinEntity => joinEntity.User)
                        .WithMany()
            );

    }

}
