using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Preflight;
// Presentation only: every safety decision belongs to the production metadata policy.
public static class MetadataReview
{
    public static IReadOnlyList<Check> Evaluate(string path,IReadOnlyDictionary<string,string> fields) =>
        FileMetadata.Assess(path,fields).Select(f=>new Check("File "+path+" / "+f.Field,f.Status,f.Detail)).ToArray();
    public static IReadOnlyList<Check> Evaluate(string path,string output)
    {
        var rows=output.Split('\n',StringSplitOptions.RemoveEmptyEntries).Select(x=>x.Trim().Split('=',2)).ToArray();
        if(rows.Any(x=>x.Length!=2)||rows.GroupBy(x=>x[0]).Any(g=>g.Count()!=1))
            return [new("File "+path,"BLOCK","Malformed metadata report.")];
        return Evaluate(path,rows.ToDictionary(x=>x[0],x=>x[1]));
    }
}
