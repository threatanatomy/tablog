+++
title = '002 - Analizando una macro maliciosa'
date = 2023-12-06T12:08:00-05:00
draft = false
translationKey = '002-malicious-macro'
description = 'En este artículo analizamos desde 0 una macro maliciosa que tiene embebida una bind shell utilizando técnicas de análisis estático y dinámico.'
cover = "/img/002-archivoOffice.png"
+++

*This article is also available in [english](/en/posts/002-analyzing-a-malicious-macro)*

## 1. Introducción

Para este primer post (segundo si contamos la [intro](/es/posts/001-intro)) decidí analizar una macro maliciosa por las siguientes razones:
1. Las macros nos permiten analizar el código que contienen, lo que consideré sería bueno para comenzar en oposición a entrar directo al análisis de un binario.
2. Las macros son frecuentemente utilizadas como "Droppers" para cargar otros malware en un sistema.
3. Las macros son frecuentemente abusadas en ataques de ingeniería social, debido a que los usuarios están acostumbrados a abrir archivos de Office.

El malware elegido para el análisis tiene como hash **97806d455842e36b67fdd2a763f97281** y puede ser descargado del siguiente [enlace](https://bazaar.abuse.ch/sample/ab518a86b77fe842821b50d182b9394d2a59d1c64183a37eb70a6cac100b39f8/).

> **Disclaimer**: Ejecutar malware en un dispositivo personal/corporativo puede poner en riesgo tu información/la información de tu empresa. Nunca ejecutes malware en un dispositivo que no ha sido específicamente configurado para el análisis.


## 2. Análisis estático
### 2.1 Obtención de los hashes
Una vez descargado y extraído el .zip, nos encontramos con un archivo .docm (archivo de Microsoft Word habilitado para macros), el cual cuenta con los siguientes hashes:

| Algoritmo | Hash                                                             |
|-----------|------------------------------------------------------------------|
| MD5       | 97806d455842e36b67fdd2a763f97281                                 |
| SHA256    | ab518a86b77fe842821b50d182b9394d 2a59d1c64183a37eb70a6cac100b39f8 |

![alt text](/img/002-hashesdocm.png "Hashes docm")


### 2.2 Análisis del archivo con olevba

Iniciamos el análisis con [*olevba*](https://github.com/decalage2/oletools/wiki/olevba), programa que nos permite detectar y extraer información de archivos que contengan macros sin tener que ejecutar los archivos.

Utilizando el parámetro -a podemos obtener un análisis inicial del archivo:

```powershell
olevba.exe -a .\ab518a86b77fe842821b50d182b9394d2a59d1c64183a37eb70a6cac100b39f8.docm
```


![alt text](/img/002-olevba-a.png "Olevba -a result")

Como parte del análisis vemos que *olevba* identifica algunas cadenas de texto sospechosas, dentro de las cuales son de principal interés los siguientes:
1. AutoOpen: función que se ejecuta al abrir el archivo, sin requerir interacción del usuario (fuera de habilitar las macros de estar deshabilitadas).
2. WScript.Shell: objeto que permite ejecutar un comando en el sistema.
3. libc.dylib y system: palabras que podrían estar relacionadas a la ejecución de comandos en sistemas MacOS.

Adicionalmente, verificamos que *olevba* detecta algunas URL como posibles IOC; será de interés analizar para qué están siendo utilizadas las URL, pues pueden ser utilizadas para almacenar binarios maliciosos, como servidor de comando y control, o ser un falso positivo.

Utilizando el parámetro -c podemos obtener el código VBA, donde visualizamos múltiples funciones:
```powershell
olevba.exe -c .\ab518a86b77fe842821b50d182b9394d2a59d1c64183a37eb70a6cac100b39f8.docm
```
1. AutoOpen(): función que se ejecuta al abrir el archivo.
2. ExecuteForWindows(code) y ExecuteForOSX(code): funciones que por el nombre parecen ejecutar código en base al sistema operativo.
3. Base64Decode(ByVal base64String): función que por el nombre parece decodificar un texto de Base64.

Analizando la función AutoOpen, verificamos que al abrir el archivo .docm se itera por las propiedades del archivo buscando la propiedad "Comments", extrae un valor de esa propiedad, obtiene parte de ese valor, lo decodifica utilizando la función Base64Decode(ByVal base64String) y se pasa como parámetro a las funciones ExecuteForWindows(code)/ExecuteForOSX(code), [dependiendo del sistema operativo](https://learn.microsoft.com/en-us/office/vba/Language/Concepts/Getting-Started/compiler-constants):

![alt text](/img/002-olevba-autoOpen.png "AutoOpen")

Al ver las propiedades del archivo, en una primera vista no se visualiza ningún comentario; sin embargo, al hacerle doble click a la propiedad podemos visualizar el contenido:

![alt text](/img/002-comments.png "Comments property")

Si quisiesemos extraer el comentario de manera programática, podemos usar powershell:
```powershell
#Asignamos el archivo a una variable
$file = "C:\Analisis\ab518a86b77fe842821b50d182b9394d2a59d1c64183a37eb70a6cac100b39f8.docm"

#Creamos el objeto Shell.Application para poder acceder a las propiedades del archivo
$shell = New-Object -ComObject Shell.Application

#Obtenemos una referencia al archivo mediante el objeto previamente creado
$item = $shell.Namespace((Get-Item $file).DirectoryName).ParseName((Get-Item $file).Name)

#Obtenemos la propiedad "Comment"
$comments = $item.ExtendedProperty("System.Comment")

#Guardamos el contenido de la propiedad en un archivo de texto
$comments > comments.txt
```

Una vez identificado el input, procedemos a analizar la función que está haciendo el decodificado; dentro de la función, se visualiza un comentario asociado a Motobit, así como las URL que *olevba* identificó como IOC:

![alt text](/img/002-decode.png "Base64Decode")

Al no estar siendo utilizadas las URL, las descartamos como falsos positivos (debido a que hay otros programas que pueden contener dichas URL sin ser maliciosos necesariamente); al buscar el texto de los comentarios en Google identificamos el [código de donde provino esa función](https://www.motobit.com/tips/detpg_Base64/).

Finalmente, analizamos las funciones a donde se pasa el texto obtenido de la propiedad "Comments" luego de ser decodificado:

![alt text](/img/002-execute.png "Execute methods")

El caso de MacOS es sencillo: se pasa el texto al intérprete de Python para ser ejecutado; por el contrario, el de Windows si tiene mayor procesamiento que resulta interesante:
1. Se asigna la variable tmp_folder a la [ruta almacenada en la variable de entorno TMP](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getspecialfolder-method)

![alt text](/img/002-tmp.png "TMP folder")

2. Se crea un [archivo con un nombre aleatorio](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/gettempname-method) (tmp_name) en dicha ruta, y se le asigna la extensión .exe.
3. Se ejecuta el archivo utilizando el objeto WScript.Shell


## 3. Análisis dinámico
### 3.1 Ejecución controlada de la macro

Ahora que ya tenemos mayor detalle de lo que realiza la macro, podemos comprobar si el análisis fue el correcto al ejecutarla de manera controlada. Al abrir el archivo, vemos que tiene un mensaje indicando que el documento fue creado por una versión mas reciente de Microsoft Office, y que las macros deben ser habilitadas para poder visualizarlo; dicho mensaje es falso, y tiene como objetivo engañar al usuario para que habilite las macros y así, gatillar el código dentro de la función AutoOpen().

![alt text](/img/002-archivoOffice.png "Enable macros message")

Antes de hacer click en "Habilitar contenido" presionamos ALT+F11 para abrir el editor de Visual Basic, donde verificamos que están las mismas funciones que identificamos con *olevba*:

![alt text](/img/002-macroview.png "Visual Basic Editor")

Como vimos al analizar las funciones con *olevba*, se extrae el contenido de la propiedad "Comments" y se decodifica utilizando la función Base64Decode(); podemos obtener el archivo decodificado editando la función AutoOpen() y utilizando el siguiente código:

```vb
Dim n As Integer
n = FreeFile()
Open "C:\analisis\orig_val.txt" For Output As #n
Print #n, orig_val
Close #n
```

Para evitar que el programa se ejecute, podemos comentar las llamadas a ExecuteForOSX(code) y ExecuteForWindows(code):

![alt text](/img/002-exportfile.png "Export file")


Analizando el archivo extraido con la herramienta [*PEStudio*](https://www.winitor.com/download), verificamos que es un ejecutable (también se podría validar la cabecera del archivo, o utilizar el comando *file* de UNIX):

![alt text](/img/002-orig_file.png "File Analysis")

Otra manera de obtener el binario (así como la ruta desde donde se ejecutará) es imprimiendo la variable *tmp_name* de la función ExecuteForWindows(code) y comentando la llamada a ("WScript.Shell").Run para evitar ejecutar el binario:

![alt text](/img/002-exforwin.png "Export full path")


### 3.2 Análisis del binario obtenido

Antes de continuar con el análisis dinámico, analizaremos brevemente de manera estática el binario que ejecuta la macro.

Primero, obtenemos el hash:

| Algoritmo | Hash                                                             |
|-----------|------------------------------------------------------------------|
| MD5       | 22C65826A225917645DBA4BF7CD019DE                                 |
| SHA256    | 21FE58C62243FCB030B1627233C77BDE7319F7E932F4F581B8F1DB49AA4C4F99 |

Buscando el hash en *VirusTotal*, verificamos que [ya se tienen firmas por la mayoría de antivirus](https://www.virustotal.com/gui/file/21fe58c62243fcb030b1627233c77bde7319f7e932f4f581b8f1db49aa4c4f99).

Abriendo el binario en *PEStudio* encontramos algunas cadenas de interés:

![alt text](/img/002-pe.png "PEStudio")

El binario parece estar suplantando a ApacheBench. Adicionalmente, verificamos que contiene una cadena que hace referencia a "C:\local0\asf\release\build-2.2.14\support\Release\ab.pdb" en la propiedad *debug*; al buscar esa cadena en internet se encuentran referencias a Shellcodes creados con Metasploit.


### 3.3 Ejecución del binario

Dado que el objetivo de este artículo era analizar una macro maliciosa, no entraré a detalle en cómo analizar estáticamente el .exe obtenido (sería interesante en un futuro artículo analizar estáticamente dicho binario); sin embargo, si me pareció importante destacar algunos hallazgos identificados al analizar el binario de manera dinámica.

Para iniciar, abrimos *Procmon*, *Process Explorer* y *TCPView*, herramientas de la suite [SysInternals](https://learn.microsoft.com/en-us/sysinternals/). En Procmon, creamos un filtro con el nombre del ejecutable (en este caso renombrado a sample.exe) y ejecutamos el archivo.

Al ejecutar el archivo validamos que simula ser ApacheBench, incluso teniendo como publicador a "Apache Software Foundation":

![alt text](/img/002-firewall.png "Windows Firewall")

Analizando *Procmon* vemos varias acciones sobre el registro, carpetas y procesos; sin embargo, de especial interés es que vemos en *TCPView* que el proceso empezó a recibir conexiones en el puerto 80:

![alt text](/img/002-tcpview.png "TCP View")

Al ver el puerto abierto, y recordar que como parte del análisis había visto referencias a shellcodes de Metasploit me pregunté... ¿realmente podría ser tan sencillo? ¿Será una bind shell esperando conexiones?

Para validar, desde otra máquina conectada a la misma red (ambas en una red propia, sin conexión con otros sistemas ni internet), utilicé *netcat* para conectarme al puerto 80 y...funcionó!

![alt text](/img/002-bindshell.png "BindShell")

Efectivamente, en *Process Explorer* podemos verificar que el proceso sample.exe inició un subproceso cmd.exe

![alt text](/img/002-processexplorer.png "Process Explorer")

Y, al intentar crear un archivo, validamos que tenemos éxito:

![alt text](/img/002-echotxt.png "Hack the planet!")
![alt text](/img/002-filecreated.png "Hack the planet!")


## 4. Conclusiones

Cuando elegí la muestra de malware, no sabía con qué me encontraría; había la posibilidad de que la macro contenga código ofuscado, que llame a powershell, o que descargue una segunda etapa de un servidor ya extinto. Afortunadamente no fue el caso y contuvo la segunda etapa ya embebida como parte del código, lo que me permitió llegar a un mayor nivel de análisis.

¡Tampoco me imagine que me encontraría con un bind shell al cual pudiese conectarme que no estuviese usando ningún tipo de encriptación! No se si fue suerte o qué, pero hizo el análisis mucho mas interesante.


Espero que les haya gustado y hayan podido aprender algo nuevo, si tuviesen alguna duda/corrección/sugerencia pueden escribirme al correo contact@threatanatomy.io.

¡Gracias y nos vemos pronto para analizar un nuevo malware!


## 5. IOC

| Archivo |  Algoritmo | Hash                                                             |
|-----------|------------|------------------------------------------------------------------|
| macro.docm       | MD5        | 97806d455842e36b67fdd2a763f97281                                 |
| macro.docm    |SHA256     | ab518a86b77fe842821b50d182b9394d2a59d1c64183a37eb70a6cac100b39f8 |
| shell.exe    | MD5     | 22C65826A225917645DBA4BF7CD019DE |
| shell.exe    | SHA256     | 21FE58C62243FCB030B1627233C77BDE7319F7E932F4F581B8F1DB49AA4C4F99 |
 





