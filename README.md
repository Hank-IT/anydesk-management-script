Ausführung mit allen Funktionen:

``./anydesk.ps1 -mode remove_and_install -onlyForegroundAccess $true -license <license>``

Entfernt alle vorhandenen AnyDesk Installationen, lädt und installiert die aktuelleste Version, setzt den Lizenz Key und setzt die Option "Interaktiver Zugang" auf "Verbindungsanfragen nur anzeigen, wenn das AnyDesk-Fenster sichtbar ist".

Entferne alle AnyDesk Installationen in "C:\Program Files" und "C:\Program Files (x86)":

``anydesk.ps1 -mode remove``

Lade die aktuelle AnyDesk Version und überprüfe die Signature:

``anydesk.ps1 -mode download``

Lade und installiere die aktuelle Anydesk Version:

``anydesk.ps1 -mode install``

Entferne alle vorhandenen AnyDesk Versionen (inklusive Custom Clients), lade und installiere die aktuelle Version:

``anydesk.ps1 -mode remove_and_install``

Zusätzlich kann bei einer Installation auch direkt eine Lizenz registriert werden:

``anydesk.ps1 -mode remove_and_install -license <license-id>``

Getestet mit:
 - AnyDesk 7.0.14 Custom Client (.exe)
 - AnyDesk 7.0.14 Custom Client (.msi)
 - AnyDesk 8.0.8 Default Client
