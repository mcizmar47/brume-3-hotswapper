using System.IO;
namespace BrumeHotswapper.Tests;
internal static class RepositoryFiles
{
    public static string Root
    {
        get
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
                if (File.Exists(Path.Combine(dir.FullName, "BrumeHotswapper.slnx"))) return dir.FullName;
            throw new InvalidOperationException("Repository root was not found.");
        }
    }
}
