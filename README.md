# DomainTcpPortChecks
Goal:
Test Active Directory's TCP and RPC ports, check of AD ports are blocked. 
https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/config-firewall-for-ad-domains-and-trusts 

Intended scenarios:
	1. Test if ports are open for trust creation.
		For example, from AADDS mgmt VM targeting OnPrem DCs.
			§ .\DomainTcpChecksV3.ps1 -DomainName OnPremMcrepro.com
	2. Test if domain ports are open between AADDS replica sets.
		For example, AADDS (McRepro.com) has 2 replica sets. 
			§ .\DomainTcpChecksV3.ps1 -DomainName McRepro.com
	3. Test if ports are open between DCs when we can't RDP into any of the 2 DCs
		a. From Azure portal with VM subscription > locate DC VM > Run Command > RunPowerShellScript
			i. Unmark line 19, update DomainName to AADDS domain name
   		ii. Paste and run the script.
   
Look for "open" for working case. "Unreachable" for non-working case.
