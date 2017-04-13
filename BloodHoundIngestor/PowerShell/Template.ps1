
function Invoke-BloodHound{
    param(
		[Alias("c")]
        [String]
        [ValidateSet('Group', 'ComputerOnly', 'LocalGroup', 'GPOLocalGroup', 'Session', 'LoggedOn', 'Trusts', 'Cache','ACL', 'Default')]
        $CollectionMethod = 'Default',

		[Alias("s")]
		[Switch]
		$SearchForest,

		[String]
		$Domain,

		[Alias("cf")]
		[Parameter(ParameterSetName = 'CSVExport')]
		[ValidateScript({ Test-Path -Path $_ })]
		[String]
		$CSVFolder = ".",

		[Alias("cp")]
		[Parameter(ParameterSetName = 'CSVExport')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CSVPrefix,

		[Alias("t")]
		[ValidateRange(1,50)]
        [Int]
        $Threads = 20,

		[Alias("sg")]
		[Switch]
        $SkipGCDeconfliction,

		[Alias("st")]
		[Switch]
		$Stealth,

		[Alias("pt")]
		[ValidateRange(50,1500)]
		[int]
		$PingTimeout = 750,

		[Alias("sp")]
		[Switch]
		$SkipPing,

		[Alias("u")]
		[Parameter(ParameterSetName = 'RESTAPI', Mandatory = $True)]
        [URI]
        $URI,

		[Alias("up")]
        [Parameter(ParameterSetName = 'RESTAPI', Mandatory = $True)]
        [String]
        [ValidatePattern('.*:.*')]
        $UserPass,

		[Alias("db")]
		[String]
		[ValidateNotNullOrEmpty()]
		$DBFileName,

		[Alias("i")]
		[Switch]
		$InMemory,

		[Alias("r")]
		[Switch]
		$RemoveDB,

		[Alias("fr")]
		[Switch]
		$ForceRebuild,

		[Alias("int")]
		[ValidateRange(500,60000)]
		[int]
		$Interval
    )

	$vars = @()

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

	$passed = [string[]]$vars

	#ENCODEDCONTENTHERE
}
