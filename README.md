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


Installationen werden nur ausgeführt, wenn AnyDesk nicht bereits unter `"C:\Program Files (x86)\AnyDesk.exe" vorhanden ist.`
