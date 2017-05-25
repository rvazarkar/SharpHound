
function Invoke-BloodHound{
    param(
        [String]
        [ValidateSet('Group', 'ComputerOnly', 'LocalGroup', 'GPOLocalGroup', 'Session', 'LoggedOn', 'Trusts', 'Cache','ACL', 'Default')]
        $CollectionMethod = 'Default',

		[Switch]
		$SearchForest,

		[String]
		$Domain,

		[ValidateScript({ Test-Path -Path $_ })]
		[String]
		$CSVFolder = $(Get-Location),

        [ValidateNotNullOrEmpty()]
        [String]
        $CSVPrefix,

		[ValidateRange(1,50)]
        [Int]
        $Threads = 20,

		[Switch]
        $SkipGCDeconfliction,

		[Switch]
		$Stealth,

		[ValidateRange(50,1500)]
		[int]
		$PingTimeout = 750,

		[Switch]
		$SkipPing,

        [URI]
        $URI,

        [String]
        [ValidatePattern('.*:.*')]
        $UserPass,

		[String]
		[ValidateNotNullOrEmpty()]
		$DBFileName,

		[Switch]
		$InMemory,

		[Switch]
		$RemoveDB,

		[Switch]
		$NoDB,

		[Switch]
		$ForceRebuild,

		[ValidateRange(500,60000)]
		[int]
		$Interval,

		[Switch]
		$Verbose
    )

	$vars = New-Object System.Collections.Generic.List[System.Object]

	$vars.Add("-c")
	$vars.Add($CollectionMethod);

	if ($Domain){
		$vars.Add("-d");
		$vars.Add($Domain);
	}

	if ($SearchForest){
		$vars.Add("-s");
	}

	if ($CSVFolder){
		$vars.Add("-f")
		$vars.Add($CSVFolder)
	}

	if ($CSVPrefix){
		$vars.Add("-p")
		$vars.Add($CSVPrefix)
	}

	if ($Threads){
		$vars.Add("-t")
		$vars.Add($Threads)
	}

	if ($SkipGCDeconfliction){
		$vars.Add("--SkipGCDeconfliction")
	}

	if ($Stealth){
		$vars.Add("--Stealth")
	}

	if ($PingTimeout){
		$vars.Add("--PingTimeout")
		$vars.Add($PingTimeout)
	}

	if ($SkipPing){
		$vars.Add("--SkipPing");
	}

	if ($URI){
		$vars.Add("--URI")
		$vars.Add($URI)
	}

	if ($UserPass){
		$vars.Add("--UserPass")
		$vars.Add($UserPass)
	}

	if ($DBFileName){
		$vars.Add("--DBFileName")
		$vars.Add($DBFileName)
	}

	if ($InMemory){
		$vars.Add("--InMemory")
	}

	if ($RemoveDB){
		$vars.Add("--RemoveDB")
	}

	if ($ForceRebuild){
		$vars.Add("--ForceRebuild")
	}

	if ($Verbose){
		$vars.Add("-v")
	}

	if ($Interval){
		$vars.Add("-i");
		$vars.Add($Interval)
	}

	if ($NoDB){
		$vars.Add("--NoDB");
	}

	$passed = [string[]]$vars.ToArray()

	#ENCODEDCONTENTHERE
}
