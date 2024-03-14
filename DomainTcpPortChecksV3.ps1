    # Domain TCP ports checks v3.1:
    #   Perform quick TCP port tests for TrustCreate operation. Modify as needed to suit your needs.
    #       Ming Chen [MSFT] 3/13/2024 & Ryan Ries [MSFT]  10/26/2023
    #    Ref1: https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/config-firewall-for-ad-domains-and-trusts
    #    Ref2: Ryan's RPC port script https://devblogs.microsoft.com/scripting/testing-rpc-ports-with-powershell-and-yes-its-as-much-fun-as-it-sounds
    #               https://ryanries.github.io/?title=test_rpc_1.1.html 
    #
    # Usage 1: 
    #       .\DomainTcpChecksV3.ps1 -DomainName <Domain Name> 
    #           Replace <Domain Name> with name of targetDomain. 
    #           For example:
    #               .\DomainTcpChecksV3.ps1 -DomainName OnPremMcRepro.com
    # Usage 2:
    #   Modify $DomainName in this script to target a specific domain. This will enable double-click on script for quick test. 
    #
    Param(
    [string]$DomainName
    )
    # $DomainName = "McRepro.com" # <<<-------- Use this to automate tests without input, good for double clicks and portal's RunPowerShellScript.
    $gShowRPCTests = $false #Set this to true to test and display all RPC ports test results instead of stopping at the first reachable RPC port
    #
    #============================================================================================================
    #   Function from Ryan's RPC port script https://devblogs.microsoft.com/scripting/testing-rpc-ports-with-powershell-and-yes-its-as-much-fun-as-it-sounds
    #       https://ryanries.github.io/?title=test_rpc_1.1.html 
    #           VERSION 1.1 https://www.powershellgallery.com/packages/Test-RPC/1.1.0/Content/Test-RPC.ps1 
    #    Note: Slight modifications made in ($Socket.Connected) and $mcRPCResult by MingChen for ease of reading the result.    
    Function Test-RPC
    {
        [CmdletBinding(SupportsShouldProcess=$True)]
        Param([Parameter(ValueFromPipeline=$True)][String[]]$ComputerName = 'localhost')
        BEGIN
        {
            Set-StrictMode -Version Latest
            $PInvokeCode = @'
            using System;
            using System.Collections.Generic;
            using System.Runtime.InteropServices;
            public class Rpc
            {
                // I found this crud in RpcDce.h
                [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
                public static extern int RpcBindingFromStringBinding(string StringBinding, out IntPtr Binding);
                [DllImport("Rpcrt4.dll")]
                public static extern int RpcBindingFree(ref IntPtr Binding);
                [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
                public static extern int RpcMgmtEpEltInqBegin(IntPtr EpBinding,
                                                        int InquiryType, // 0x00000000 = RPC_C_EP_ALL_ELTS
                                                        int IfId,
                                                        int VersOption,
                                                        string ObjectUuid,
                                                        out IntPtr InquiryContext);
                [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
                public static extern int RpcMgmtEpEltInqNext(IntPtr InquiryContext,
                                                        out RPC_IF_ID IfId,
                                                        out IntPtr Binding,
                                                        out Guid ObjectUuid,
                                                        out IntPtr Annotation);
                [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
                public static extern int RpcBindingToStringBinding(IntPtr Binding, out IntPtr StringBinding);
                public struct RPC_IF_ID
                {
                    public Guid Uuid;
                    public ushort VersMajor;
                    public ushort VersMinor;
                }
                // Returns a dictionary of <Uuid, port>
                public static Dictionary<int, string> QueryEPM(string host)
                {
                    Dictionary<int, string> ports_and_uuids = new Dictionary<int, string>();
                    int retCode = 0; // RPC_S_OK 
                    IntPtr bindingHandle = IntPtr.Zero;
                    IntPtr inquiryContext = IntPtr.Zero;                
                    IntPtr elementBindingHandle = IntPtr.Zero;
                    RPC_IF_ID elementIfId;
                    Guid elementUuid;
                    IntPtr elementAnnotation;
                    try
                    {                    
                        retCode = RpcBindingFromStringBinding("ncacn_ip_tcp:" + host, out bindingHandle);
                        if (retCode != 0)
                            throw new Exception("RpcBindingFromStringBinding: " + retCode);
                        retCode = RpcMgmtEpEltInqBegin(bindingHandle, 0, 0, 0, string.Empty, out inquiryContext);
                        if (retCode != 0)
                            throw new Exception("RpcMgmtEpEltInqBegin: " + retCode);
                        do
                        {
                            IntPtr bindString = IntPtr.Zero;
                            retCode = RpcMgmtEpEltInqNext (inquiryContext, out elementIfId, out elementBindingHandle, out elementUuid, out elementAnnotation);
                            if (retCode != 0)
                                if (retCode == 1772)
                                    break;
                            retCode = RpcBindingToStringBinding(elementBindingHandle, out bindString);
                            if (retCode != 0)
                                throw new Exception("RpcBindingToStringBinding: " + retCode);
                            string s = Marshal.PtrToStringAuto(bindString).Trim().ToLower();
                            if(s.StartsWith("ncacn_ip_tcp:"))
                                if (ports_and_uuids.ContainsKey(int.Parse(s.Split('[')[1].Split(']')[0])) == false) ports_and_uuids.Add(int.Parse(s.Split('[')[1].Split(']')[0]), elementIfId.Uuid.ToString());
                            RpcBindingFree(ref elementBindingHandle);
                        }
                        while (retCode != 1772); // RPC_X_NO_MORE_ENTRIES
                    }
                    catch(Exception ex)
                    {
                        Console.WriteLine(ex);
                        return ports_and_uuids;
                    }
                    finally
                    {
                        RpcBindingFree(ref bindingHandle);
                    }
                    return ports_and_uuids;
                }
            }
    '@
        }
        PROCESS
        {
            [Bool]$EPMOpen = $False
            [Bool]$bolResult = $False
            $Socket = New-Object Net.Sockets.TcpClient
            Try
            {                    
                $Socket.Connect($ComputerName, 135)
                If ($Socket.Connected)
                {
                    $EPMOpen = $True
                }
                $Socket.Close()                    
            }
            Catch
            {
                $Socket.Dispose()
            }
            If ($EPMOpen)
            {
                Add-Type $PInvokeCode
                # Dictionary <Uuid, Port>
                $RPC_ports_and_uuids = [Rpc]::QueryEPM($Computer)
                $PortDeDup = ($RPC_ports_and_uuids.Keys) | Sort-Object -Unique
                #----------Mod begin------------MingChen
                $mcRPCResult=$False
                Foreach ($Port In $PortDeDup) {
                    $Socket = New-Object Net.Sockets.TcpClient
                    Try {
                        $Socket.Connect($Computer, $Port)
                        If ($Socket.Connected) {
                            if ($gShowRPCTests -eq $True) {
                                Write-Output "    RPC $Port Reachable"
                                $mcRPCResult=($mcRPCResult -and $True)
                            } else {
                                $mcRPCResult=$True
                                break
                            }
                        }
                        $Socket.Close()
                    }
                    Catch {
                        if ($gShowRPCTests -eq $True) {
                            Write-Output "    RPC $Port is Unreachable <<-=-=-=-=<<<<"
                        }
                        $mcRPCResult=$False
                        $Socket.Dispose()
                    }
                }
                If ($mcRPCResult -eq $True) {
                    Write-Output "    One of these RPC ports is Open: `n      [$PortDeDup]"
                } else {
                    Write-Output ">>>>>>> RPC ports Unreachable  <<-=-=-=-=<<<<`n    Some or all of these RPC ports are Unreachable:`n      [$PortDeDup]`n    Please open TCP 49152-65535 RPC ports for LSA, SAM, NetLogon (*) per:`n    https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/config-firewall-for-ad-domains-and-trusts`n`n"
                }
                #--------Mod end-----------------
            }
        }
        END
        {
        }
    }
    #==Main Script========================================================================
    Write-output "`n+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=`n"
        $LocalDomain = $env:userdnsdomain
        if ($LocalDomain -ne $null){
            $CmdOutput = nltest /dnsgetdc:$LocalDomain
            $LocalDCs = $CmdOutput |  Where-Object { $_ -match $LocalDomain } | ForEach-Object {  
                $line = $_ -split " " | Select-Object -First 4 
                $line.Trim()  
            }  | Where-Object { $_ -match $LocalDomain }
            Write-Output "Local Domain = $LocalDomain" "Local Domain Controllers `n   $LocalDCs"
        } 

    $CmdOutput = nltest /dnsgetdc:$DomainName
    $Targets= $CmdOutput |  Where-Object { $_ -match $domainName } | ForEach-Object {  
        $line = $_ -split " " | Select-Object -First 4 
        $line.Trim()  
    }  | Where-Object { $_ -match $domainName }
    if ($Targets -ne $null){ 
        $Ports = 135,389,636,3268,3269,53,88,445   # https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/config-firewall-for-ad-domains-and-trusts
        Write-output "`nTarget Domain = $DomainName" "Target Domain Controllers: `n   $Targets"
        [System.Net.Dns]::GetHostByName($env:computerName) | Select-Object HostName, addresslist | Format-List
        $Targets | ForEach-Object {
            $Computer = $_
                Write-output "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=`nTarget Domain Controllers:"
                Test-NetConnection -ComputerName $Computer -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Format-List
                $Ports | ForEach-Object {
                    $Port=$_
                    if (Test-NetConnection -ComputerName $Computer -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue ) {
                        Write-output "  Tcp port $Port is Open"
                    } else {
                        Write-output"  Tcp Port $Port is Unreachable <<-=-=-=-=<<<<"
                    }
                }
                Write-Progress "Spot checking the RPC Endpoint Mapper Ports on [$Computer], this spot check might take some time.. "
                Test-RPC -ComputerName $Computer
        }
    } else {
        Write-Output "`n>>>>Error<<<< `n      The command [nltest /dnsgetdc:$domainName] does not find any domain controllers for [$DomainName]. `n      To fix this, please configure Conditional Forwarders for [$DomainName] on the DNS server and run the command again..`n"
    }
