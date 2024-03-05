+++
title = '005 - Analizando un agente de C2 - Parte 3: el agente - Análisis dinámico'
date = 2024-02-12T12:03:49-05:00
draft = false
translationKey = '005-dotnet-agent'
description = 'En este artículo analizaremos de manera dinámica el agente de C2 que obtuvimos previamente y evaluaremos formas de interactuar con él para entender su funcionamiento.'
+++

*This article is also available in [english](/en/posts/005-analyzing-a-dotnet-c2-agent-part3-dynamic-analysis/)*

## 1. Introducción

En [la segunda parte de este artículo](/es/posts/004-analyzing-a-dotnet-c2-agent/) analizamos de manera estática el binario .exe que obtuvimos de una macro maliciosa; en dicho análisis, identificamos que el programa había sido desarrollado en .NET, lo que facilitó el análisis debido a que el lenguaje intermedio (IL) que utiliza dicho framework es muy similar al código fuente original, lo que permite que sea facilmente decompilado.

En esta sección analizaremos de manera dinámica el binario para validar que nuestro análisis estático haya sido el correcto, así como desarrollar formas de interactuar con el agente.

> **Disclaimer**: Ejecutar malware en un dispositivo personal/corporativo puede poner en riesgo tu información/la información de tu empresa. Nunca ejecutes malware en un dispositivo que no ha sido específicamente configurado para el análisis.

## 2. Análisis dinámico del binario

### 2.1 Configuración del ambiente y conexión inicial

Como parte del análisis estático identificamos que, luego de esperar unos segundos, el programa se intenta comunicar con la IP *162.245.191.217* en los puertos 9149, 15198, 17818, 27781 y 29224, iterando entre ellos hasta conseguir una conexión exitosa. Podemos comprobar que efectivamente el programa realiza dichos intentos de conexión utilizando *TCPView* o *Process Monitor*:

![alt text](/img/005_TCPView1.png "Connection in TCP View")

![alt text](/img/005_Procmon1.png "Connection in Process Monitor")

Dado que el binario necesita una respuesta exitosa del servidor para continuar, podemos proceder de dos formas:

1. Modificar la IP de destino en ejecución utilizando DNSpy
2. Modificar Remnux para que intercepte el tráfico dirgido al servidor

En esta ocasión opté por la segunda opción, la cual puede ser implementada modificando las reglas de firwall de Remnux; para ello, podemos redirigir todo el tráfico con destino a la IP del servidor a un puerto en específico en Remnux:

```bash
sudo iptables -t nat -A PREROUTING -i ens33 -p tcp -d 162.245.191.217  -j DNAT --to-destination 10.0.0.3:4321
```

Como parte del análisis estático identificamos que el programa obtiene una respuesta del servidor, la separa en base al caracter "=" y en base a la primera parte del mensaje (lo que está antes del caracter "=") realiza una acción. Podemos hacer una prueba enviando un valor que sabemos que el programa entiende y ver si se sigue el camino esperado:
```python
import socket
import struct

message_content = "thyTumb=LoremIpsumTest"
print(message_content)

HOST = '0.0.0.0'
PORT = 4321


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    print("Server is listening...")
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        conn.sendall(message_content.encode())
        print("Data sent to the client.")

```
![alt text](/img/005_expected.png "Message to send")

Sin embargo, rápidamente nos damos cuenta que enviar un mensaje no será tan simple; el agente implementa lógica customizada para determinar el tamaño del mensaje y así saber cuando dejar de "leer" datos:
![alt text](/img/005-breakpoint.png "Identification logic")

Adicionalmente, debido a diferencias en cómo C# (en lo que está escrito el agente) y Python (el servidor que estamos usando para suplantar al servidor real) manejan mensajes TCP, es necesario hacer adecuaciones en el código para que el agente pueda entender el mensaje:
```python
import socket
import struct

message_content = "thyQumb=LoremIpsumTest"

message_length = len(message_content.encode())
packed_length = struct.pack('!I', message_length)

reversed_length = packed_length[::-1]

reversed_length = reversed_length + b'\x00' * (5 - len(reversed_length))

message_to_send = reversed_length + message_content.encode()
print(message_to_send)

HOST = '0.0.0.0'  
PORT = 4321     

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    print("Server is listening...")
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        conn.sendall(message_to_send)
        print("Data sent to the client.")


```

Con dichas modificaciones verificamos que el mensaje llega correctamente al agente:
![alt text](/img/005-fixedcode.png "Agent receives response")

Durante el análisis puede demorar mucho esperar a que se cumplan las condiciones necesarias para que el malware se comunique con el servidor, por lo que extraer la parte del código que queremos entender y utilizarla en otro programa nos puede ayudar a comprender qué está pasando de manera mas efectiva; para comprender bien cómo Python enviaba los mensajes y cómo .NET los recibía, hice un pequeño programa que me permitió validar la respuesta de cada etapa del proceso:
![alt text](/img/005-customdebug.png "Debugging using Visual Studio")

Una vez que logramos enviar información al agente en un "idioma" que entienda, implementar la lógica de recibir información del agente toma poco tiempo. Finalmente tenemos cómo enviar comandos al agente de Comando y Control y podemos verificar cómo se comporta en la práctica.



### 2.2 Análisis de las capacidades del agente

Al igual que en el artículo anterior, analizaremos algunas capacidades que ofrece el agente para verificar cómo se comportan durante su ejecución:

#### 2.2.1 Listar procesos

Al recibir el comando "geyTtavs", nos esperamos que se envíe el ID de cada proceso, seguido por el nombre de cada proceso siguiendo el patrón
*IDProceso1>NombreProceso1>0>\<IDProceso2>NombreProceso2>0><*. Utilizando Wireshark, podemos comprobar que efectívamente se envía la información de dicha manera:
![alt text](/img/005-listarProcesos.png "DNSpy view of parsing processess")
![alt text](/img/005-listarProcesosWireshark.png "Wireshark view of parsing processess")

En el servidor, podemos modificar nuestro script para parsear mejor la información recibida:
![alt text](/img/005-listarProcesosParseado.png "Server view of parsing processess")
![alt text](/img/005-taskexplorer.png "Server view of parsing processess")



#### 2.2.2 Establecer persistencia

Otro de las funciones que ofrecía el agente de C2 que identificamos durante el análisis estático es la de establecer persistencia, la cual podemos comprobar utilizando *Autoruns* y *Process monitor* 
![alt text](/img/005-persistencia.png "Command to establish persistence")
![alt text](/img/005-persistenciaPM.png "Persistence through Registry key")
![alt text](/img/005-persistencia2.png "Persistence through Registry key")

El agente de C2 utiliza la llave de registro _HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\Run_ para definir que el agente se ejecute con cada inicio de sesión ([técnica T1547.001 en MITRE ATT&CK](https://attack.mitre.org/techniques/T1547/001/)).


#### 2.2.3 Exfiltrar archivos

El agente ofrece al atacante la capacidad de exfiltrar archivos mediante el comando "afyTile", para lo cual recibe la ruta del archivo y procede a enviarlo al servidor de C2; podemos actualizar nuestro servidor para interactuar con dicha función y confirmar la lectura del archivo usando *Wireshark* y *Process Monitor*:
![alt text](/img/005-exfil1.png "File exfiltrated to C2")
![alt text](/img/005-exfil2.png "File read on filesystem")
![alt text](/img/005-exfil3.png "Data sent through Wireshark")


#### 2.2.4 Descargar y ejecutar programas

Una de las capacidades mas interesantes que ofrece el agente es la de descargar y ejecutar binarios del servidor de C2, por lo que un atacante puede ampliar su ataque utilizando capacidades no inicialmente disponibles en el malware. Uno de los casos donde constantemente vemos dicho tipo de técnica es con las [organizaciones que](https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/) [despliegan](https://www.darkreading.com/threat-intelligence/-gold-melody-access-broker-unpatched-servers) [ransomware](https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/lockbit), en las que organizaciones conocidas como *Brokers de Acceso Inicial (IAB)* venden el acceso que consiguieron en una empresa a organizaciones de Ransomware como Lockbit y Conti.

![alt text](/img/005-download.png "Download and execute")

Para mi prueba inicial, hice que la aplicación descargue y ejecute la calculadora de Windows:
![alt text](/img/005-calc.png "Opening a calculator")

Sin embargo, dado que ejecutar la calculadora es aburrido, decidí descargar Wannacry simulando lo que podría hacer un atacante real:
{{< youtube 9e0o0iAIYeo >}}

### 2.3 Demo de servidor de C2

Luego de analizar algunas de las capacidades que ofrecía el agente (facilitado por la fácil decompilación de .NET), logré implementar un servidor capaz de comunicarse con el agente basandome únicamente en el código de este; dentro de las funcionalidades que implementé están la de listar procesos, obtener información del sistema, ejecutar comandos, establecer persistencia, listar archivos en un directorio, y descargar y ejecutar binarios.

En el siguiente video se muestran algunas de las capacidades:
{{< youtube kr9-kPQhMEo >}}

Como se aprecia en el video, el agente establece cada minuto una comunicación con el servidor de Comando y Control, lo que permite al atacante enviar distintos comandos; dentro de los revisados, está la descarga y ejecución de binarios, donde se descargó y ejecutó [*Mimikatz*](https://github.com/gentilkiwi/mimikatz), el listado de procesos de sistema, donde identificamos el proceso de *Mimikatz*, y el de obtener información del sistema, donde obtuvimos el nombre de la máquina, el usuario, la versión de Windows, así como la ruta donde se está ejecutando el agente.

Adicionalmente, se evidencia cómo aparecen dichas actividades en herramientas como *Process Explorer*, *Process Monitor*, *TCP View* y *Wireshark*, lo que nos permite entender a detalle las acciones gatilladas por cada capacidad del malware.

En el video no se muestran todas las capacidades implementadas, así como otras que ofrece el agente que no fueron adecuadas al servidor falso (eliminar archivos, sacar capturas de pantalla, etc), por lo que recomiendo a los lectores hacer ingeniería inversa al binario e implementarlas como forma de aprendizaje.

## 3. Conclusiones

Cuando inicié el análisis de este malware solo sabía que contenía una macro maliciosa, mas no que embebía un agente de Comando y Control, el cual sería capaz de decompilar, analizar, y realizar una POC para interactuar con él. El malware obtenido fue la oportunidad perfecta para practicar distintas técnicas de análisis, tanto estático como dinámico, permitiendo realizar ingeniería reversa sin tener que leer código ensamblador.

En un futuro artículo analizaré un nuevo malware, idealmente uno que no esté basado en Macros ni .NET para documentar nuevas técnicas de análisis; aun así, independientemente de la herramienta de análisis, la metodoloǵia es la misma, por lo que invito a los lectores a replicar lo realizado y así practicar.

De tener algún feedback o sugerencia no olvides escribirme a contact@threatanatomy.io!


## 4. Mapeo MITRE ATT&CK

| ID        | Táctica             | Técnica                                                               | Descripción                                                                                                                                |
|-----------|---------------------|-----------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| T1059.003 | Ejecución           | Command and Scripting Interpreter: Windows Command Shell              | Se utilizó el método Process.Start para iniciar nuevos procesos                                                                            |
| T1547.001 | Persistencia        | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Se utilizó una llave de registro para establecer persistencia |
| T1070.004 | Evasión de defensas | Indicator Removal: File Deletion                                      | El agente tiene la capacidad de eliminar archivos                                                                                          |
| T1057     | Descubrimiento      | Process Discovery                                                     | El agente tiene la capacidad de listar procesos                                                                                            |
| T1082     | Descubrimiento      | System Information Discovery                                          | El agente tiene la capacidad de obtener información del sistema                                                                            |
| T1027.010 | Evasión de defensas | Obfuscated Files or Information: Command Obfuscation                  | Se utilizó el reemplazo de caracteres para ofuscar comandos                                                                                |
| T1113     | Colección           | Screen Capture                                                        | El agente tiene la capacidad de sacar capturas de pantalla                                                                                 |
| T1005     | Colección           | Data from Local System                                                | El agente tiene la capacidad de obtener información de archivos del sistema                                                                |
| T1571     | Comando y Control   | Non-Standard Port                                                     | El agente no utiliza puertos comunes para comunicarse con el servidor de C2                                                                |
| T1095     | Comando y Control   | Non-Application Layer Protocol                                        | El agente se comunica mediante TCP, interactuando directo con el flujo de datos                                                            |
| T1041     | Comando y Control   | Exfiltration Over C2 Channel                                          | El agente exfiltra información utilizando la conexión establecida con el servidor de C2                                                    |

## 5. IOC

| IOC                                                                           | Tipo              | Descripción                                              |
|-------------------------------------------------------------------------------|-------------------|----------------------------------------------------------|
| 59211a4e0f27d70 c659636746b61945a                                              | Hash MD5          | Hash del agente de C2                                    |
| 162.245.191.217                                                               | IP                | IP a donde se comunica el agente                         |
| HKEY_CURRENT_USER\ Software\Microsoft \Windows\CurrentVersion\ Run\haijwivetsgVr | Llave de registro | Llave que el agente utiliza para establecer persistencia |
