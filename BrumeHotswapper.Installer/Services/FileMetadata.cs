using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;

public record NumericFileMetadata(char Type, string Mode, uint Uid, uint Gid);
public record MetadataFinding(string Field, string Status, string Detail);
public static class FileMetadata
{
    public static NumericFileMetadata ParseListing(string output)
    {
        // Only leading fields matter; dates and filenames (including spaces) are ignored.
        var match = Regex.Match(output.TrimEnd('\r','\n'), @"\A([-dlbcps][r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-])\s+[0-9]+\s+([0-9]+)\s+([0-9]+)\s+[^\r\n]+\z");
        if (!match.Success || !uint.TryParse(match.Groups[2].Value, out uint uid) || !uint.TryParse(match.Groups[3].Value, out uint gid))
            throw new SafeFailure("Numeric ls metadata is malformed.");
        string symbolic = match.Groups[1].Value;
        int bits = 0;
        for (int group = 0; group < 3; group++) {
            int index = 1 + group * 3, shift = (2-group)*3;
            if (symbolic[index] == 'r') bits |= 4 << shift;
            if (symbolic[index+1] == 'w') bits |= 2 << shift;
            if (symbolic[index+2] is 'x' or 's' or 't') bits |= 1 << shift;
            if (symbolic[index+2] is 's' or 'S') bits |= group == 0 ? 2048 : 1024;
            if (symbolic[index+2] is 't' or 'T') bits |= 512;
        }
        return new(symbolic[0], Convert.ToString(bits,8).PadLeft(3,'0'), uid, gid);
    }
    public static string SymbolicMode(string mode, char type = '-')
    {
        if (!Regex.IsMatch(mode, @"\A[0-7]{3,4}\z") || type is not ('-' or 'd' or 'l')) throw new SafeFailure("Invalid expected file mode.");
        int bits = Convert.ToInt32(mode,8); var text = new char[10]; text[0]=type;
        for (int group=0; group<3; group++) {
            int permission=(bits >> ((2-group)*3)) & 7, i=1+group*3;
            text[i]=(permission&4)!=0?'r':'-'; text[i+1]=(permission&2)!=0?'w':'-';
            text[i+2]=(permission&1)!=0?'x':'-';
            if ((bits & (group==0?2048:group==1?1024:512)) != 0)
                text[i+2]=group==2?((permission&1)!=0?'t':'T'):((permission&1)!=0?'s':'S');
        }
        return new string(text);
    }
    public static string ListingCommand(string path) => "LC_ALL=C ls -ldn " + ConfigurationGenerator.Quote(path);
    // Reused inside atomic compare-before-replace commands, including upload staging and rollback.
    public static string MatchesCommand(string path, string mode, char type = '-') =>
        $"test ! -L {ConfigurationGenerator.Quote(path)} && test \"$({ListingCommand(path)} | awk '{{print $1 \":\" $3 \":\" $4}}')\" = '{SymbolicMode(mode,type)}:0:0'";
    public static IReadOnlyDictionary<string,string> Commands(string path)
    {
        if (!DeploymentPlanning.Paths.Contains(path)) throw new SafeFailure("Unrecognized metadata path.");
        string q=ConfigurationGenerator.Quote(path);
        return new Dictionary<string,string> {
            ["symlink"]=$"if [ -L {q} ]; then echo 1; else echo 0; fi",
            ["exists"]=$"if [ -e {q} ]; then echo 1; else echo 0; fi",
            ["regular"]=$"if [ -f {q} ]; then echo 1; else echo 0; fi",
            ["readable"]=$"if [ -r {q} ]; then echo 1; else echo 0; fi",
            ["listing"]=ListingCommand(path), ["size"]=$"wc -c < {q}",
            ["sha256"]=$"sha256sum {q} | awk '{{print $1}}'"
        };
    }
    public static async Task<Dictionary<string,string>> ReadAsync(IRouterTransport router,string path,CancellationToken ct)
    {
        var fields=new Dictionary<string,string>();
        foreach(var (field,command) in Commands(path)) {
            if(fields.GetValueOrDefault("exists")=="0" && field is not "exists" and not "symlink") break;
            try {
                var value=(await router.ExecuteAsync(command,ct)).Trim();
                if(field=="listing") {
                    var parsed=ParseListing(value);
                    fields["type"]=parsed.Type.ToString(); fields["mode"]=parsed.Mode;
                    fields["uid"]=parsed.Uid.ToString(); fields["gid"]=parsed.Gid.ToString();
                } else fields[field]=Regex.IsMatch(value,field=="sha256"?@"\A[a-fA-F0-9]{64}\z":@"\A[0-9]{1,20}\z")?value:"invalid";
            } catch(OperationCanceledException) {throw;}
            catch {
                if(field=="listing") foreach(var key in new[]{"type","mode","uid","gid"}) fields[key]="unavailable";
                else fields[field]="unavailable";
            }
        }
        return fields;
    }
    public static bool SafeMode(string path,string mode) => Regex.IsMatch(mode,@"\A[0-7]{3,4}\z") &&
        (Convert.ToInt32(mode,8)&0xE12)==0 && (path!="/usr/bin/rtp2.sh" || Convert.ToInt32(mode,8)==493);
    public static IReadOnlyList<MetadataFinding> Assess(string path,IReadOnlyDictionary<string,string> fields)
    {
        string Get(string key)=>fields.GetValueOrDefault(key,"missing");
        var checks=new List<MetadataFinding>();
        void Check(string field,bool pass,string detail)=>checks.Add(new(field,pass?"PASS":"BLOCK",detail));
        Check("symlink",Get("symlink")=="0","Expected no symlink.");
        if(Get("exists")=="0") {
            checks.Add(new("existence",path=="/usr/bin/rtp2.sh"?"BLOCK":"WARN",path is "/root/vpn-watch-locations.tsv" or "/root/reboot-guards.tsv"?"Expected legacy absence; generated file is required after installation.":"Absent."));
            return checks;
        }
        Check("exists",Get("exists")=="1","Expected existing file.");
        Check("regular",Get("regular")=="1" && Get("type")=="-","Independent test and listing must identify a regular file.");
        Check("readability",Get("readable")=="1","Expected readable file.");
        foreach(var key in new[]{"uid","gid"}) Check(key,Get(key)=="0",key.ToUpperInvariant()+"="+(uint.TryParse(Get(key),out _)?Get(key):"unavailable")+"; expected 0.");
        string mode=Get("mode"),expected=path=="/usr/bin/rtp2.sh"?"755":path.EndsWith(".sh")?"700":"600";
        bool safe=SafeMode(path,mode), exact=safe && Convert.ToInt32(mode,8)==Convert.ToInt32(expected,8);
        checks.Add(new("mode",!safe?"BLOCK":exact?"PASS":"WARN","Observed "+(Regex.IsMatch(mode,@"\A[0-7]{3,4}\z")?mode:"unavailable")+"; expected "+expected+(safe&&!exact?"; safe legacy normalization during installation.":".")));
        Check("hash",Regex.IsMatch(Get("sha256"),@"\A[a-fA-F0-9]{64}\z"),"SHA-256 format/readability checked; private hashes withheld.");
        Check("size",long.TryParse(Get("size"),out long size)&&size>=0,"Size: "+(long.TryParse(Get("size"),out size)?size.ToString():"unavailable"));
        return checks;
    }
    public static FileState Validate(string path,IReadOnlyDictionary<string,string> fields)
    {
        var failure=Assess(path,fields).FirstOrDefault(x=>x.Status=="BLOCK");
        if(failure!=null) throw new SafeFailure("Target metadata failed: "+failure.Field+". "+failure.Detail);
        return fields.GetValueOrDefault("exists")=="0"?new(path,"","",false):new(path,fields["sha256"].ToLowerInvariant(),fields["mode"],true);
    }
}
