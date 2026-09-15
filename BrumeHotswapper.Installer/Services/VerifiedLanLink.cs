using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
namespace BrumeHotswapper.Installer.Services;

// A configured LAN subnet, corroborated by its current kernel interface/address assignment.
public sealed record VerifiedLanLink(string Interface,string Address,uint Network,int Prefix)
{
    private static uint Number(string address)
    {
        if(!IPAddress.TryParse(address,out var ip)||ip.AddressFamily!=AddressFamily.InterNetwork)
            throw new SafeFailure("LAN IPv4 evidence is invalid.");
        var b=ip.GetAddressBytes();return (uint)b[0]<<24|(uint)b[1]<<16|(uint)b[2]<<8|b[3];
    }
    public static VerifiedLanLink Discover(string address,string netmask,string addresses)
    {
        uint ip=Number(address), mask=Number(netmask), inverse=~mask;
        if(mask==0||(inverse&(inverse+1))!=0)throw new SafeFailure("LAN subnet evidence is invalid.");
        int prefix=System.Numerics.BitOperations.PopCount(mask);
        var links=new List<string>();
        foreach(var line in addresses.Split('\n',StringSplitOptions.RemoveEmptyEntries)) {
            var m=Regex.Match(line,@"^\d+:\s+([A-Za-z0-9_.-]+)(?:@[A-Za-z0-9_.-]+)?:?\s+inet\s+([0-9.]+)/([0-9]+)\s+.*\bscope global(?: |$)");
            if(m.Success&&m.Groups[2].Value==address&&int.TryParse(m.Groups[3].Value,out int p)&&p==prefix)
                links.Add(m.Groups[1].Value);
        }
        if(links.Count!=1)throw new SafeFailure("A unique live interface for the configured LAN subnet could not be established.");
        return new(links[0],address,ip&mask,prefix);
    }
    public bool ContainsDirectRoute(string route)
    {
        // Exact connected-route shape: no gateway, default, nexthop, encap or unrecognized attributes.
        var m=Regex.Match(route,@"\A([0-9.]+)/([0-9]+) dev ([A-Za-z0-9_.-]+) proto kernel scope link src ([0-9.]+)(?: metric [0-9]+)?\z");
        if(!m.Success||m.Groups[3].Value!=Interface||m.Groups[4].Value!=Address||!int.TryParse(m.Groups[2].Value,out int prefix)||prefix!=Prefix)return false;
        try{return Number(m.Groups[1].Value)==Network;}catch(SafeFailure){return false;}
    }
}
