@{
	ModuleVersion = '1.0.0'
	Author = 'xBurningGiraffe'
	Description = 'Swiss Army Knife of RaderSec Operations'
	PowerShellVersion = '5.1'
	FunctionsToExport = '*'
	RootModule = 'Invoke-RaderSec.psm1'
	NestedModules = @(
		'Invoke-RaderIP_Hunter.psm1',
		'Invoke-RaderSnD.psm1',
		'Start-IntuneManagement.psm1',
		'Invoke-Rader_Recon.psm1',
		'Find-SecurityClients.psm1',
		'Invoke-BEC_IR.psm1',
		'Start-RaderSecQuery.psm1'
		)
}
