using Microsoft.EntityFrameworkCore;
using RealCordinator.Api.Models;

namespace RealCordinator.Api.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options) { }

        public DbSet<User> Users => Set<User>();
    }
}
