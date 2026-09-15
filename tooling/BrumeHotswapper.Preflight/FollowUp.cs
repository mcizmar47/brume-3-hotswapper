using System.Text.RegularExpressions;
using BrumeHotswapper.Installer.Core;
using BrumeHotswapper.Installer.Services;
namespace BrumeHotswapper.Preflight;
public sealed partial class Runner
{
    private async Task FirmwareChecksAsync(RouterIdentity identity,CancellationToken ct)
    {
        await Step("Firmware compatibility",async()=>{
            await RouterPrerequisites.VerifyFirmwareAsync(read,identity,ct);
            Add("Firmware compatibility",true,CompatibilityCatalog.Classify(identity.Rtp2Hash)+"; shared catalog, hash, marker, anchor and syntax checks passed.");
        });
        await Step("Upload capability",async()=>{
            var kind=await session.ProbeUploadAsync(ct);
            Add("Upload capability",true,"Verified "+kind+" using the production transport probe; no router files created.");
        });
    }
    public async Task RunFollowUpAsync(RouterIdentity identity,CancellationToken ct)
    {
        Add("Identity/version",identity.IsBrume && CompatibilityCatalog.TestedFirmware.Contains(identity.Firmware),"Production authentication/identity result checked against the supported firmware catalog.");
        if(!identity.IsBrume)return;
        await FirmwareChecksAsync(identity,ct);
        await Step("Required utilities",async()=>{await read.ExecuteAsync(RouterPrerequisites.CapabilitiesCommand,ct);Add("Required utilities",true,"Production command prerequisites passed.");});
        foreach(var path in DeploymentPlanning.Paths)
            await Step("File "+path,async()=>{
                var fields=await FileMetadata.ReadAsync(read,path,ct);
                var findings=MetadataReview.Evaluate(path,fields);
                if(findings.All(f=>f.Status=="PASS")) Add("File "+path,true,"Shared production metadata policy passed.");
                else foreach(var finding in findings.Where(f=>f.Status!="PASS")) report(finding);
            });
        await Step("VPN prerequisites",async()=>{
            var profiles=await new VpnDiscovery(read).DiscoverPoliciesAsync(ct);
            var profile=VpnDiscovery.AutoSelect(profiles)??throw new SafeFailure("A unique VPN policy was not established.");
            await new RouterInspection(read,new KillSwitchVerifier()).VerifyPolicySlotsAsync(profile,ct);
            Add("VPN prerequisites",true,"Shared policy/group, slot ownership and active-peer agreement checks passed.");
            await RoutingDiagnostics.VerifyAsync(read,profile.PolicySection,report,ct);
        });
    }
}
// Shared production checks; IPv6 is independent of the selected kill-switch choice.
public static class RoutingDiagnostics
{
    public static async Task VerifyAsync(IRouterTransport router,string policy,Action<Check> report,CancellationToken ct)
    {
        try {
            await new KillSwitchVerifier().VerifyAsync(router,policy,ct);
            bool enabled=await KillSwitchVerifier.ReadEnabledAsync(router,policy,ct);
            report(new("Kill-switch configuration","PASS",enabled ? "Enabled; GL enforcement integration verified." : "Disabled; preserved as configured. Selected VPN integration verified."));
        } catch(OperationCanceledException){throw;}
        catch(Exception e){report(new("Kill-switch configuration","BLOCK",e is SafeFailure?e.Message:"Required integration evidence unavailable; details withheld."));}
        try {
            await Ipv6Compatibility.VerifyAsync(router,ct);
            report(new("IPv6 compatibility","PASS","IPv6 disabled; IPv4 promotion prerequisite satisfied."));
        } catch(OperationCanceledException){throw;}
        catch(Exception e){report(new("IPv6 compatibility","BLOCK",e is SafeFailure?e.Message:"IPv6 prerequisite unavailable; details withheld."));}
    }
}
