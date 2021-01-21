<#
    Fichier original Get-RSATTools.ps1
    Fonctionalité : Interface de gestion des outils RSAT pour l'administration Windows
    Mise en forme GUI
    Traduction en Français
    Git : https://github.com/ludovicferra
#> 

#Masquer la console powershell
function HidePOWSHConsole {
    Add-Type -Name Window -Namespace Console -MemberDefinition '[DllImport("Kernel32.dll")]public static extern IntPtr GetConsoleWindow(); [DllImport("user32.dll")]public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);'
    $consolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($consolePtr, 0)
}
HidePOWSHConsole | Out-Null

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName PresentationFramework
[System.Windows.Forms.Application]::EnableVisualStyles()
#Main
$Main                            = New-Object system.Windows.Forms.Form
$Main.ClientSize                 = '600,400'
$Main.text                       = "Get-RSATTester"
$Main.BackColor                  = "#f5a623"
$Main.TopMost                    = $false
$Main.FormBorderStyle            = 'Fixed3D'
$Main.MaximizeBox                = $false
$Main.icon = [Drawing.Icon]::ExtractAssociatedIcon((Get-Command powershell).Path)
#Boite de résultats
$TextBoxResult                   = New-Object system.Windows.Forms.TextBox
$TextBoxResult.multiline         = $true
$TextBoxResult.ReadOnly         = $true
$TextBoxResult.width             = 590
$TextBoxResult.height            = 323
$TextBoxResult.location          = New-Object System.Drawing.Point(5,30)
$TextBoxResult.Font              = 'Microsoft Sans Serif,8'
$TextBoxResult.Scrollbars        = "Vertical"
#Texte de boite
$Label1                          = New-Object system.Windows.Forms.Label
$Label1.text                     = "Gestion des outils RSAT sur cette machine :"
$Label1.AutoSize                 = $false
$Label1.width                    = 372
$Label1.height                   = 11
$Label1.location                 = New-Object System.Drawing.Point(10,10)
$Label1.Font                     = 'Microsoft Sans Serif,8'
#Bouton d'installation
$ButtonInstall                   = New-Object system.Windows.Forms.Button
$ButtonInstall.text              = "Installer tous les RSAT"
$ButtonInstall.width             = 285
$ButtonInstall.height            = 30
$ButtonInstall.visible           = $false
$ButtonInstall.location          = New-Object System.Drawing.Point(5,361)
$ButtonInstall.Font              = 'Microsoft Sans Serif,9'
#Bouton de désinstallation
$ButtonUnInstall                   = New-Object system.Windows.Forms.Button
$ButtonUnInstall.text              = "Désinstaller tous les RSAT"
$ButtonUnInstall.width             = 285
$ButtonUnInstall.height            = 30
$ButtonUnInstall.visible           = $false
$ButtonUnInstall.location          = New-Object System.Drawing.Point(310,361)
$ButtonUnInstall.Font              = 'Microsoft Sans Serif,9'
#Concaténation de l'UI
$Main.controls.AddRange(@($TextBoxResult,$Label1,$ButtonInstall,$ButtonUnInstall))
#Valide que le programme soit lancé en tant qu'administrateur
if (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    $message = "Cet outil necessite une élévation"
    [System.Windows.MessageBox]::Show($message,'Élévation','Ok','Error') | Out-Null
    break
}
#Récupère les outils RSAT non installés
$NonInstalledRSAT = Get-WindowsCapability -Name RSAT* -Online | Where-Object State -ne "Installed" #Remonte uniquement les RSAT non installés 
if ($NonInstalledRSAT.length -gt 0 ) { 
    $TextBoxResult.text = "Les outils RSAT Suivants ne sont pas installés :`r`n"
    $TextBoxResult.text += $NonInstalledRSAT | Select-Object state,Displayname | ForEach-Object { Write-Output "$($_.state) : $($_.Displayname)`r`n"}
    $ButtonInstall.Visible = $true
    $ButtonUnInstall.visible = $true
}
else { 
    $TextBoxResult.text = "L'ensemble des RSAT disponibles online sont installés`r`n"
    $ButtonUnInstall.visible = $true
}

$ButtonInstall.Add_Click({
    $ButtonInstall.text = "Installation en cours, Patienter..."
    $ButtonInstall.enabled = $false
    $TextBoxResult.text += InstallRSAT -All
    $ButtonInstall.text = "Installation terminée"
})
$ButtonUnInstall.Add_Click({
    $ButtonUnInstall.text = "Désinstallation en cours, Patienter..."
    $ButtonUnInstall.enabled = $false
    $TextBoxResult.text += InstallRSAT -Uninstall | Out-String
    $ButtonUnInstall.text = "Désinstallation terminée"
})
function InstallRSAT {
<#
    From code of Martin Bengtsson
    Git : https://github.com/imabdk/Powershell
    Blog: www.imab.dk
    Twitter: @mwbengtsson
#> 
[CmdletBinding()]
param(
    [parameter(Mandatory=$false)] [ValidateNotNullOrEmpty()] [switch]$All,
    [parameter(Mandatory=$false)] [ValidateNotNullOrEmpty()] [switch]$Uninstall
)
    #Création d'un retour de logs :
    $logs = @()
    #Récupère l'état de redémarrage en attente par le registre
    $CBSRebootKey = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore
    $WURebootKey = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction Ignore
    if ($CBSRebootKey -OR $WURebootKey) { $TestPendingRebootRegistry = $true }
    else { $TestPendingRebootRegistry = $false }
    #Récupération de la version de Built Windows
    [int]$minimalbuild = 17763
    $WindowsBuild = (Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue).BuildNumber
    #Récupération de l'existaance de serveur WSUS
    $WUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction Ignore).WUServer
    if ($WindowsBuild -gt $minimalbuild) {
        $message = "La version Build de Windows 10 est correcte pour installer les ouilts RSAT.`r`nVersion de build actuelle : $WindowsBuild`r`n"
        $message += "***********************************************************"
        $logs += Write-Output $message
        if ($WUServer) {
            $message = "Un serveur WSUS local a été trouvé configuré par la stratégie de groupe : $WUServer`r`n"
            $message += "(Vous devrez peut-être configurer des paramètres supplémentaires par GPO si les choses ne fonctionnent pas)`r`n`r`n"
            $message += "L'objet de stratégie de groupe à voir est le suivant:`r`n'Spécifiez les paramètres d'installation et de réparation de composants facultatifs'`r`n"
            $message += "Vérifiez qu'il soit actif :`r`n'Téléchargez le contenu de réparation et les fonctionnalités optionnelles directement à partir de Windows Update...'`r`n"
            $message += "***********************************************************"
            $logs += Write-Output $message
            [System.Windows.MessageBox]::Show($message,'WUServer','Ok','Information') | Out-Null
        }
        if ($TestPendingRebootRegistry) {
            $message = "Un redémarrage est en attente.`r`nLe script continuera, mais les RSAT risquent de ne pas être installés / désinstallés correctement`r`n"
            $message += "***********************************************************`r`n"
            $logs += Write-Output $message
            $message += "On continue tout de même ?"
            $choicereboot = [System.Windows.MessageBox]::Show($message,'Redemarrage en attente','YesNo','Warning')
        }
        else { $choicereboot = 'Yes' }
        if ($choicereboot -eq 'Yes') {
            if ($PSBoundParameters["All"]) {
                #Installation tous les outils RSAT disponibles
                $logs += Write-Output "Installation tous les outils RSAT disponibles"
                $Install = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat*" -AND $_.State -eq "NotPresent"}
                if ($Install) {
                    foreach ($Item in $Install) {
                        $RsatItem = $Item.Name
                        $message = "Installation de :`r`n$($RsatItem | Out-String)"
                        $logs += Write-Output $message
                        [System.Windows.MessageBox]::Show($message,'Installation','Ok','Information') | Out-Null
                        try { Add-WindowsCapability -Online -Name $RsatItem }
                        catch [System.Exception] {
                            $message = "Erreur à l'installation de :`r`n$RsatItem`r`n"
                            $message += "Erreur :`r`n$($_.Exception.Message)"
                            $logs += Write-Output $message
                            [System.Windows.MessageBox]::Show($message,'Erreur installation','Ok','Error') | Out-Null
                        }
                    }
                }
                else {
                    $message = "Toutes les fonctionnalités RSAT semblent déjà installées"
                    $logs += Write-Output $message
                    [System.Windows.MessageBox]::Show($message,'Déjà installées','Ok','Information')  | Out-Null
                }
            }
            #Désinstallation de tous les outils RSTAT
            if ($PSBoundParameters["Uninstall"]) {
                #Récupération des tous les outils RSAT installés
                $Installedoriginal = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat*" -AND $_.State -eq "Installed"}
                $message = Write-Output "Produits découverts à désinstaller :`r`n"
                $message += $Installedoriginal.Name | Format-Table -HideTableHeaders | Out-String
                $logs += Write-Output $message
                $message += Write-Output "`r`nProcéder à la désinstallation ?"
                $choiceuninstall = [System.Windows.MessageBox]::Show($message,'Désinstallation','YesNo','Information')
                if ($choiceuninstall -eq 'Yes') {
                    #Première requête pour les fonctionnalités RSAT installées
                    $Installed = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat*" -AND $_.State -eq "Installed" -AND $_.Name -notlike "Rsat.ServerManager*" -AND $_.Name -notlike "Rsat.GroupPolicy*" -AND $_.Name -notlike "Rsat.ActiveDirectory*"} 
                    if ($Installed) {
                        # Désinstallation de la première série de fonctionnalités RSAT - certaines fonctionnalités semblent être verrouillées jusqu'à ce que d'autres soient désinstallées en premier
                        $logs += Write-Output "Désinstallation de la première série de fonctionnalités RSAT`r`n"
                        foreach ($Item in $Installed) {
                            $RsatItem = $Item.Name
                            $logs += Write-Output "Désinstallation de la fonctionnalité RSAT :`r`n$RsatItem"
                            try { Remove-WindowsCapability -Name $RsatItem -Online }
                            catch [System.Exception] { 
                                $logs += Write-Output "Erreur à la désinstallation de : $RsatItem`r`n"
                                $logs += Write-Output "Avec l'erreur :`r`n$($_.Exception.Message)"
                                $logs += Write-Output $message
                            }
                        }   
                    }
                    #Interrogation des fonctionnalités RSAT installées pour finir la désinstallation
                    $Installed = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat*" -AND $_.State -eq "Installed"}
                    if ($Installed) { 
                        $logs += Write-Output "Désinstallation de la seconde série de fonctionnalités RSAT"
                        foreach ($Item in $Installed) {
                            $RsatItem = $Item.Name
                            $logs += Write-Output "Désinstallation de $RsatItem"
                            try { Remove-WindowsCapability -Name $RsatItem -Online }
                            catch [System.Exception] {
                                $logs += Write-Output "Erreur à la désinstallation de :`r`n$RsatItem`r`n"
                                $logs += Write-Output= "Avec l'erreur :`r`n$($_.Exception.Message)"
                            }
                        } 
                    }
                    else {
                        $message = "Toutes les fonctionnalités RSAT semblent déjà désinstallées"
                        [System.Windows.MessageBox]::Show($message,'Déjà installées','Ok','Information')  | Out-Null
                    }
                }
                else { $logs += Write-Output "`r`nDésinstallation annulée`r`n" }
            }
        }
    }
    else {
        $message = "La version Build de Windows 10 ne correspond pas pour installer les ouilts RSAT à la demande.`r`nVersion de build actuelle : $WindowsBuild`r`n(Nécéssite une version $minimalbuild ou supérieure)"
        $logs = Write-Output "Cette version de windows n'est pas supportée"
        [System.Windows.MessageBox]::Show($message,'Mauvaise Build','Ok','Warning') | Out-Null
    }
Return $logs
}
[void]$Main.ShowDialog()