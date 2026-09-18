using System.IO;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Tests;
public class SharedProductionTests
{
    [Theory]
    [InlineData("-rwxr-xr-x    1 0 0 55880 ... /root/hotswapper-main.sh", "755", '-', 0, 0)]
    [InlineData("-rwx------ 1 0 0 10 Sep 12 2026 /root/name with spaces", "700", '-', 0, 0)]
    [InlineData("-rw------- 1 123 456 10 Sep 12 2026 /root/name", "600", '-', 123, 456)]
    [InlineData("-rwxrwxrwx 1 0 0 10 ...", "777", '-', 0, 0)]
    [InlineData("-rwsr-sr-t 1 0 0 10 ...", "7755", '-', 0, 0)]
    [InlineData("-rwSr-Sr-T 1 0 0 10 ...", "7644", '-', 0, 0)]
    [InlineData("drwx------ 2 0 0 4096 ...", "700", 'd', 0, 0)]
    [InlineData("lrwxrwxrwx 1 0 0 10 ... name -> target", "777", 'l', 0, 0)]
    public void ParsesActualBusyBoxLeadingFields(string listing,string mode,char type,uint uid,uint gid)
    {
        var parsed=FileMetadata.ParseListing(listing);
        Assert.Equal(new NumericFileMetadata(type,mode,uid,gid),parsed);
        Assert.Equal(listing[..10],FileMetadata.SymbolicMode(mode,type));
    }
    [Theory]
    [InlineData("")][InlineData("total 1\n-rwxr-xr-x 1 0 0 55880 ...")]
    [InlineData("-rwxr-xr-x 1 root root 55880 ...")][InlineData("-rwxr-xr-z 1 0 0 55880 ...")]
    [InlineData("-rwxr-xr-x 1 9999999999999 0 55880 ...")]
    public void MalformedListingBlocks(string listing)=>Assert.Throws<SafeFailure>(()=>FileMetadata.ParseListing(listing));
    [Theory]
    [InlineData("-rwxr-xr-x",0,0,"WARN")][InlineData("-rwx------",0,0,"PASS")]
    [InlineData("-rwxrwxr-x",0,0,"BLOCK")][InlineData("-rwxr-xrwx",0,0,"BLOCK")]
    [InlineData("-rwsr-xr-x",0,0,"BLOCK")][InlineData("-rwxr-Sr-x",0,0,"BLOCK")]
    [InlineData("-rwxr-xr-T",0,0,"BLOCK")][InlineData("-rwxr-xr-x",10,0,"BLOCK")]
    [InlineData("-rwxr-xr-x",0,10,"BLOCK")][InlineData("lrwxrwxrwx",0,0,"BLOCK")]
    public void InstallerAppliesMetadataSafetyPolicy(string symbolic,uint uid,uint gid,string expected)
    {
        var parsed=FileMetadata.ParseListing($"{symbolic} 1 {uid} {gid} 55880 ... file with spaces");
        var fields=new Dictionary<string,string>{{"exists","1"},{"regular","1"},{"symlink",symbolic[0]=='l'?"1":"0"},{"readable","1"},{"type",parsed.Type.ToString()},{"mode",parsed.Mode},{"uid",parsed.Uid.ToString()},{"gid",parsed.Gid.ToString()},{"size","55880"},{"sha256",new string('a',64)}};
        if(expected=="BLOCK") Assert.Throws<SafeFailure>(()=>FileMetadata.Validate("/root/hotswapper-main.sh",fields));
        else FileMetadata.Validate("/root/hotswapper-main.sh",fields);
    }
    [Fact] public void ReplacementGuardsQuoteSpacesAndCheckRootMetadata()
    {
        var command=FileMetadata.MatchesCommand("/root/file with ' quote", "700");
        Assert.Contains("LC_ALL=C ls -ldn '/root/file with '\"'\"' quote'",command);
        Assert.Contains("'-rwx------:0:0'",command);
    }
    [Fact] public void NoUnavailableMetadataCommandsInProduction()
    {
        var root=RepositoryFiles.Root;
        var files=Directory.EnumerateFiles(Path.Combine(root,"installer"),"*.cs",SearchOption.AllDirectories)
            .Where(p=>!p.Contains(Path.DirectorySeparatorChar+"tests"+Path.DirectorySeparatorChar)&&!p.Contains(Path.DirectorySeparatorChar+"obj"+Path.DirectorySeparatorChar)&&!p.Contains(Path.DirectorySeparatorChar+"bin"+Path.DirectorySeparatorChar))
            .Concat(Directory.EnumerateFiles(Path.Combine(root,"firmware"),"*.sh",SearchOption.AllDirectories));
        foreach(var path in files)Assert.False(Regex.IsMatch(File.ReadAllText(path),@"\bstat\b|\bfind\b[^\r\n]*-printf"),Path.GetFileName(path));
    }
}
